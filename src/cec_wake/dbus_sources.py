"""DBus wake sources: screensaver, logind IdleHint, logind PrepareForSleep.

python3-dbus and python3-gobject are optional at runtime; the daemon operates
on Wayland sources alone if they are unavailable.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from typing import Any

from cec_wake.threads import spawn_daemon_thread

LOG = logging.getLogger("cec-wake")

try:
    import dbus
    import dbus.mainloop.glib
    from gi.repository import GLib

    HAVE_DBUS = True
except ImportError:  # pragma: no cover - exercised by test stubs instead.
    HAVE_DBUS = False

# Screensaver interfaces monitored on the session bus.
# Covers lock-based wake events across common desktop environments.
# Not emitted by KDE 6.x for DPMS-only idle; the Wayland path handles that case.
SCREENSAVER_INTERFACES = [
    "org.freedesktop.ScreenSaver",
    "org.kde.screensaver",
    "org.gnome.ScreenSaver",
    "org.cinnamon.ScreenSaver",
]

LOGIND_BUS_NAME = "org.freedesktop.login1"
LOGIND_MANAGER_PATH = "/org/freedesktop/login1"
LOGIND_MANAGER_IFACE = "org.freedesktop.login1.Manager"
LOGIND_SESSION_IFACE = "org.freedesktop.login1.Session"
DBUS_PROPS_IFACE = "org.freedesktop.DBus.Properties"

# Resume delay after system suspend to allow display and CEC adapter
# re-initialisation before sending commands.
SUSPEND_RESUME_DELAY_SEC = 3

__all__ = [
    "DBUS_PROPS_IFACE",
    "HAVE_DBUS",
    "LOGIND_BUS_NAME",
    "LOGIND_MANAGER_IFACE",
    "LOGIND_MANAGER_PATH",
    "LOGIND_SESSION_IFACE",
    "SCREENSAVER_INTERFACES",
    "SUSPEND_RESUME_DELAY_SEC",
    "run_dbus_loop",
]

Dispatch = Callable[[str], None]


def _logind_session_path() -> str:
    """
    Return the D-Bus object path for the current logind session.

    Logind encodes the session ID into the path by replacing each character
    outside [A-Za-z0-9_] with '_' followed by its two-hex-digit ASCII value.

    Raises RuntimeError if XDG_SESSION_ID is not set.
    """
    session_id = os.getenv("XDG_SESSION_ID")
    if not session_id:
        raise RuntimeError(  # noqa: TRY003 - message documents the missing env var.
            "XDG_SESSION_ID is not set; logind session monitoring unavailable."
        )

    return f"/org/freedesktop/login1/session/{_encode_logind_path_segment(session_id)}"


def _encode_logind_path_segment(segment: str) -> str:
    encoded_chars = []
    for ch in segment:
        if ch.isalnum() or ch == "_":
            encoded_chars.append(ch)
        else:
            encoded_chars.append(f"_{ord(ch):02x}")
    return "".join(encoded_chars)


def _subscribe_screensaver(session_bus: Any, dispatch: Dispatch) -> None:
    """
    Register ActiveChanged and SessionIdleChanged receivers for all known
    screensaver interfaces on the session bus.

    add_signal_receiver() is a local registration that cannot fail for a
    missing remote service; all interfaces are always registered.
    """

    def make_active_handler(iface: str) -> Callable[[bool], None]:
        def handler(is_active: bool) -> None:  # noqa: FBT001 - dbus signal payload.
            LOG.debug("ActiveChanged: is_active=%s iface=%s", is_active, iface)
            if not is_active:
                dispatch(f"{iface}:ActiveChanged")

        return handler

    def make_idle_handler(iface: str) -> Callable[[bool], None]:
        def handler(is_idle: bool) -> None:  # noqa: FBT001 - dbus signal payload.
            LOG.debug("SessionIdleChanged: is_idle=%s iface=%s", is_idle, iface)
            if not is_idle:
                dispatch(f"{iface}:SessionIdleChanged")

        return handler

    for iface in SCREENSAVER_INTERFACES:
        session_bus.add_signal_receiver(
            make_active_handler(iface),
            signal_name="ActiveChanged",
            dbus_interface=iface,
        )
        session_bus.add_signal_receiver(
            make_idle_handler(iface),
            signal_name="SessionIdleChanged",
            dbus_interface=iface,
        )
        LOG.debug("Subscribed to %s ActiveChanged + SessionIdleChanged", iface)


def _subscribe_logind_idle(system_bus: Any, dispatch: Dispatch) -> None:
    """
    Subscribe to logind Session PropertiesChanged to detect IdleHint
    True -> False transitions (session resumed from idle).

    Seeds the initial IdleHint state at subscription time so a daemon
    restart mid-idle correctly tracks the first True -> False transition.
    """
    try:
        session_path = _logind_session_path()
    except RuntimeError as exc:
        LOG.warning("Logind idle monitoring unavailable: %s", exc)
        return

    prev_idle: bool | None = None

    try:
        obj = system_bus.get_object(LOGIND_BUS_NAME, session_path)
        props = dbus.Interface(obj, DBUS_PROPS_IFACE)
        prev_idle = bool(props.Get(LOGIND_SESSION_IFACE, "IdleHint"))
        LOG.debug("Initial logind IdleHint: %s", prev_idle)
    except dbus.DBusException as exc:
        LOG.warning("Could not read initial IdleHint: %s", exc)

    def on_properties_changed(
        iface: str, changed: dict[str, Any], _invalidated: Any
    ) -> None:
        nonlocal prev_idle
        if iface != LOGIND_SESSION_IFACE:
            return
        if "IdleHint" not in changed:
            return
        idle_now = bool(changed["IdleHint"])
        LOG.debug("logind IdleHint: %s -> %s", prev_idle, idle_now)
        if prev_idle is True and not idle_now:
            dispatch("logind:IdleHint")
        prev_idle = idle_now

    system_bus.add_signal_receiver(
        on_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface=DBUS_PROPS_IFACE,
        bus_name=LOGIND_BUS_NAME,
        path=session_path,
    )
    LOG.debug("Subscribed to logind IdleHint on %s", session_path)


def _subscribe_prepare_for_sleep(system_bus: Any, dispatch: Dispatch) -> None:
    """
    Subscribe to logind PrepareForSleep to detect system resume from suspend.

    PrepareForSleep(True)  = system is about to suspend (no action)
    PrepareForSleep(False) = system has resumed from suspend

    A short delay is inserted on resume to allow display and CEC adapter
    re-initialisation before sending commands.
    """

    def on_prepare_for_sleep(sleeping: bool) -> None:  # noqa: FBT001 - dbus signal.
        if sleeping:
            return
        LOG.debug("logind: PrepareForSleep(False) - system resuming from suspend")

        def _delayed_dispatch() -> None:
            time.sleep(SUSPEND_RESUME_DELAY_SEC)
            dispatch("logind:PrepareForSleep")

        spawn_daemon_thread(_delayed_dispatch, name="cec-resume-delay")

    system_bus.add_signal_receiver(
        on_prepare_for_sleep,
        signal_name="PrepareForSleep",
        dbus_interface=LOGIND_MANAGER_IFACE,
        bus_name=LOGIND_BUS_NAME,
        path=LOGIND_MANAGER_PATH,
    )
    LOG.debug("Subscribed to logind PrepareForSleep")


def run_dbus_loop(dispatch: Dispatch) -> None:
    """
    Subscribe to DBus wake signals and run a GLib main loop in a daemon thread.

    Monitors three signal sources on behalf of wider DE compatibility:

      Screensaver ActiveChanged / SessionIdleChanged (session bus)
        Covers screen-lock-based wake events on GNOME, Cinnamon, and KDE
        when the screen locker is active.

      logind IdleHint PropertiesChanged (system bus)
        Covers idle resume on X11 sessions and compositors that report
        idle state to logind.  On KDE 6.x Wayland, IdleHint never
        transitions; the Wayland path handles that configuration.

      logind PrepareForSleep (system bus)
        Covers system resume from suspend.  A short delay is inserted
        before dispatching to allow the display and CEC adapter to
        re-initialise after suspend.

    GLib main loop is isolated to this thread.  The Wayland event loop
    and main thread are unaffected if this thread fails to start.
    """
    if not HAVE_DBUS:
        LOG.warning(
            "python3-dbus or python3-gobject not available; "
            "DBus wake sources (screensaver, logind) disabled. "
            "Install python3-dbus and python3-gobject to enable."
        )
        return

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    active_sources = []

    try:
        session_bus = dbus.SessionBus()
        _subscribe_screensaver(session_bus, dispatch)
        active_sources.append("screensaver")
    except dbus.DBusException as exc:
        LOG.warning("Cannot connect to session bus: %s", exc)

    try:
        system_bus = dbus.SystemBus()
        _subscribe_logind_idle(system_bus, dispatch)
        _subscribe_prepare_for_sleep(system_bus, dispatch)
        active_sources.append("logind")
    except dbus.DBusException as exc:
        LOG.warning("Cannot connect to system bus: %s", exc)

    if not active_sources:
        LOG.warning("No DBus wake sources could be subscribed")
        return

    LOG.info("Active DBus wake sources: %s", active_sources)

    loop = GLib.MainLoop()
    try:
        loop.run()
    except Exception as exc:
        LOG.warning("DBus GLib main loop exited: %s", exc)
