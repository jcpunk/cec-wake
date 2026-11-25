"""Wayland wake sources: ext-idle-notify-v1 and zwlr-output-power-management-v1.

python3-pywayland is optional at runtime, mirroring the DBus sources in
``cec_wake.dbus_sources``: a host running only the DBus/logind sources (for
example a headless or X11 session) should not need pywayland installed.  Use
``--no-wayland`` or ``CEC_WAKE_NO_WAYLAND=1`` to skip this module entirely
without needing the package present.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

LOG = logging.getLogger("cec-wake")

try:
    from pywayland.client import Display as WaylandDisplay
    from pywayland.protocol.ext_idle_notify_v1 import ExtIdleNotifierV1
    from pywayland.protocol.wayland import WlOutput, WlSeat

    HAVE_WAYLAND = True
except ImportError:  # pragma: no cover - exercised by test stubs instead.
    HAVE_WAYLAND = False

# zwlr_output_power_management_unstable_v1 is not yet advertised by KWin 6.x
# but is included for forward compatibility.  Import failure is non-fatal.
try:
    from pywayland.protocol.wlr_output_power_management_unstable_v1 import (
        ZwlrOutputPowerManagerV1,
    )

    HAVE_WLR_OUTPUT_POWER = True
except ImportError:  # pragma: no cover
    HAVE_WLR_OUTPUT_POWER = False

# Seconds between Wayland reconnect attempts after unexpected disconnect.
WAYLAND_RECONNECT_DELAY_SEC = 5

# zwlr_output_power_management_v1 mode values (from protocol XML).
WLR_OUTPUT_POWER_MODE_OFF = 0
WLR_OUTPUT_POWER_MODE_ON = 1

__all__ = [
    "HAVE_WAYLAND",
    "HAVE_WLR_OUTPUT_POWER",
    "WAYLAND_RECONNECT_DELAY_SEC",
    "run_wayland_loop",
]

Dispatch = Callable[[str], None]

# ---------------------------------------------------------------------------
# Protocol handlers
# ---------------------------------------------------------------------------


def _setup_idle_notify(
    globals_: dict[str, Any], idle_timeout_msec: int, dispatch: Dispatch
) -> bool:
    """
    Bind ext_idle_notifier_v1 and register a notification object.

    Returns True if the protocol was available and the notification was
    registered, False otherwise.
    """
    idle_notifier = globals_.get("idle_notifier")
    seat = globals_.get("seat")

    if not idle_notifier or not seat:
        LOG.warning(
            "ext_idle_notifier_v1 or wl_seat not available from compositor; "
            "idle-based wake detection disabled"
        )
        return False

    notification = idle_notifier.get_idle_notification(idle_timeout_msec, seat)

    def on_idled(_notification: Any) -> None:
        LOG.debug("ext-idle-notify: idled")

    def on_resumed(_notification: Any) -> None:
        LOG.debug("ext-idle-notify: resumed")
        dispatch("ext-idle-notify-v1:resumed")

    notification.dispatcher["idled"] = on_idled
    notification.dispatcher["resumed"] = on_resumed

    LOG.info("Subscribed to ext-idle-notify-v1 (timeout %dms)", idle_timeout_msec)
    return True


def _setup_output_power(globals_: dict[str, Any], dispatch: Dispatch) -> bool:
    """
    Bind zwlr_output_power_manager_v1 and register mode handlers for all
    current outputs.

    Returns True if the protocol was available, False otherwise.
    """
    if not HAVE_WLR_OUTPUT_POWER:
        return False

    manager = globals_.get("output_power_manager")
    if not manager:
        LOG.debug(
            "zwlr_output_power_manager_v1 not advertised by compositor; "
            "will activate automatically if KDE adds support"
        )
        return False

    outputs = globals_.get("outputs", [])
    for output in outputs:
        _bind_output_power(manager, output, dispatch)

    LOG.info(
        "Subscribed to zwlr-output-power-management-v1 (%d output(s))",
        len(outputs),
    )
    return True


def _bind_output_power(manager: Any, output: Any, dispatch: Dispatch) -> None:
    """
    Bind a zwlr_output_power_v1 object for a single wl_output and register
    a mode change handler.

    Calls dispatch() when an output transitions from off to on, indicating
    the display has been powered back on.
    """
    power = manager.get_output_power(output)
    prev_mode: dict[str, int | None] = {"value": None}

    def on_mode(_power: Any, mode: int) -> None:
        LOG.debug(
            "zwlr-output-power: mode %s -> %d",
            prev_mode["value"],
            mode,
        )
        if (
            prev_mode["value"] == WLR_OUTPUT_POWER_MODE_OFF
            and mode == WLR_OUTPUT_POWER_MODE_ON
        ):
            dispatch("zwlr-output-power-management-v1:mode-on")
        prev_mode["value"] = mode

    def on_failed(_power: Any) -> None:
        LOG.warning(
            "zwlr-output-power: output power management unavailable for this output"
        )

    power.dispatcher["mode"] = on_mode
    power.dispatcher["failed"] = on_failed


# ---------------------------------------------------------------------------
# Display discovery
# ---------------------------------------------------------------------------


def _wayland_socket_path(display_name: str) -> str:
    """
    Return the filesystem path of a Wayland socket.

    Compositors create their socket under $XDG_RUNTIME_DIR.  systemd user
    services always have that variable set to /run/user/<uid>, so the path is
    derived from it.  When it is unset (manual launch with no session) the
    display name is used literally, as a historical fallback.
    """
    runtime_dir = os.getenv("XDG_RUNTIME_DIR")
    if runtime_dir:
        return str(Path(runtime_dir) / display_name)
    return display_name


def _wayland_socket_connectable(display_name: str) -> bool:
    """
    Return True if the Wayland socket for display_name exists and accepts a
    connection.

    A non-blocking AF_UNIX connect is performed and immediately closed.  This
    proves the listening socket is present and reachable without speaking the
    Wayland protocol.  A socket file left behind by a crashed compositor
    (bound, not listening) is rejected, so the caller can skip it.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)  # noqa: FBT003 - stdlib positional-only API.
        try:
            sock.connect(_wayland_socket_path(display_name))
        except BlockingIOError:
            return True
        except OSError:
            return False
        return True
    finally:
        sock.close()


def _scan_wayland_displays() -> list[str]:
    """
    Return Wayland display names present under $XDG_RUNTIME_DIR, ordered by
    numeric index (wayland-0 before wayland-1).  Only names of the form
    wayland-<digits> are considered.
    """
    runtime_dir = os.getenv("XDG_RUNTIME_DIR")
    matches = []
    if runtime_dir:
        try:
            entries = list(Path(runtime_dir).iterdir())
        except OSError:
            entries = []
        for entry in entries:
            name = entry.name
            if not name.startswith("wayland-"):
                continue
            suffix = name[len("wayland-") :]
            if suffix.isdigit():
                matches.append((int(suffix), name))
    matches.sort(key=lambda item: item[0])
    return [name for _, name in matches]


def _pick_wayland_display() -> str | None:
    """
    Return the display name to connect to, or None if none is available.

    Preference order:
      1. An explicit WAYLAND_DISPLAY override, but only when its socket is
         connectable, so a stale or mistyped override can never win.
      2. The lowest-index wayland-N socket discovered under $XDG_RUNTIME_DIR.

    Each candidate is validated before selection so a dead socket left by a
    crashed compositor is skipped in favor of a live one.
    """
    override = os.getenv("WAYLAND_DISPLAY")
    if override and _wayland_socket_connectable(override):
        return override

    for name in _scan_wayland_displays():
        if _wayland_socket_connectable(name):
            return name

    return None


# ---------------------------------------------------------------------------
# Connection lifetime + event loop
# ---------------------------------------------------------------------------


def _bind_and_run(display: Any, dispatch: Dispatch, idle_timeout_msec: int) -> None:
    """Discover available protocols, bind handlers, and run the event loop."""
    registry = display.get_registry()
    globals_: dict[str, Any] = {}

    def on_global(registry: Any, name: int, interface: str, version: int) -> None:
        if interface == "ext_idle_notifier_v1":
            globals_["idle_notifier"] = registry.bind(name, ExtIdleNotifierV1, version)
        elif interface == "wl_seat":
            globals_["seat"] = registry.bind(name, WlSeat, version)
        elif interface == "wl_output":
            outputs = globals_.setdefault("outputs", [])
            outputs.append(registry.bind(name, WlOutput, version))
        elif interface == "zwlr_output_power_manager_v1" and HAVE_WLR_OUTPUT_POWER:
            globals_["output_power_manager"] = registry.bind(
                name, ZwlrOutputPowerManagerV1, version
            )

    registry.dispatcher["global"] = on_global
    display.roundtrip()

    active_sources = []

    if _setup_idle_notify(globals_, idle_timeout_msec, dispatch):
        active_sources.append("ext-idle-notify-v1")

    if _setup_output_power(globals_, dispatch):
        active_sources.append("zwlr-output-power-management-v1")

    if not active_sources:
        LOG.error(
            "No Wayland wake sources available. "
            "The connected compositor did not advertise ext-idle-notify-v1 "
            "or zwlr-output-power-management-v1. Ensure a Wayland compositor "
            "(e.g. KWin) is running on this display."
        )
        return

    LOG.info("Active Wayland wake sources: %s", active_sources)
    display.roundtrip()

    try:
        while display.dispatch(block=True) != -1:
            pass
        LOG.warning("Compositor disconnected")
    except Exception as exc:
        LOG.warning("Wayland event loop error: %s", exc)


def _run_wayland_connection(
    dispatch: Dispatch, idle_timeout_msec: int, wayland_display: str
) -> None:
    """
    Run one Wayland connection lifetime: connect, bind protocols, event loop.

    Returns normally when the connection drops.  All exceptions are caught
    and logged so the outer reconnect loop continues cleanly.
    """
    display = WaylandDisplay()
    try:
        display.connect()
    except Exception as exc:
        LOG.error(  # noqa: TRY400 - connect failures are logged without tracebacks.
            "Cannot connect to Wayland display %s: %s", wayland_display, exc
        )
        return

    try:
        _bind_and_run(display, dispatch, idle_timeout_msec)
    except Exception as exc:
        LOG.warning("Wayland connection error: %s", exc)
    finally:
        display.disconnect()


def run_wayland_loop(dispatch: Dispatch, idle_timeout_msec: int) -> None:
    """
    Connect to the Wayland compositor and monitor for display wake events.

    The Wayland display is auto-discovered on each attempt from the active
    session, so a stale or mistyped WAYLAND_DISPLAY override is tolerated and
    never requires a unit edit to recover.  Reconnects automatically on
    compositor disconnect.  Runs until the process exits.

    A no-op if python3-pywayland is unavailable; callers should check
    HAVE_WAYLAND first if a one-time log message is wanted.
    """
    if not HAVE_WAYLAND:
        LOG.warning(
            "python3-pywayland not available; Wayland wake sources "
            "(ext-idle-notify-v1, zwlr-output-power-management-v1) disabled. "
            "Install python3-pywayland to enable."
        )
        return

    while True:
        display_name = _pick_wayland_display()
        if display_name is None:
            LOG.warning(
                "No Wayland display available; reconnecting in %ds...",
                WAYLAND_RECONNECT_DELAY_SEC,
            )
            time.sleep(WAYLAND_RECONNECT_DELAY_SEC)
            continue
        _run_wayland_connection(dispatch, idle_timeout_msec, display_name)
        LOG.info(
            "Wayland display %s disconnected; reconnecting in %ds...",
            display_name,
            WAYLAND_RECONNECT_DELAY_SEC,
        )
        time.sleep(WAYLAND_RECONNECT_DELAY_SEC)
