#!/usr/bin/python3
"""
cec_wake_daemon.py - HDMI-CEC wake controller for Linux desktops

Sends a CEC Power-On + Active-Source command when the display comes back on.

Wake event sources
------------------
All sources are optional at runtime.  The daemon starts with whatever subset
is available and logs which sources are active.  All sources share a single
non-blocking lock so only one cec-client invocation runs at a time.

Wayland sources (python3-pywayland required):

  1. ext-idle-notify-v1  (current KDE/Wayland mechanism)
     Registers an idle notification with a fixed timeout (default 60s, well
     below any practical screen-off setting).  The compositor fires 'idled'
     after the configured timeout of continuous user inactivity, then fires
     'resumed' when activity is detected.  Because the notification resets
     to active state after each 'resumed' event, spurious wakes during
     normal use are impossible regardless of how short the timeout is.  The
     timeout only needs to be shorter than the display power-off setting so
     that 'idled' fires before the screen goes dark, arming the object for
     'resumed' on wake.

  2. zwlr-output-power-management-v1  (future-proofing)
     Emits a 'mode' event directly when display power changes (on/off).
     Not currently advertised by KWin 6.x, but included so the daemon
     automatically benefits from it if KDE adds support in a future release.
     No configuration required; fires on actual DPMS state transitions.

DBus sources (python3-dbus + python3-gobject required):

  3. Screensaver ActiveChanged / SessionIdleChanged (session bus)
     Covers screen lock/unlock wake events on GNOME, Cinnamon, and KDE
     when the screen locker is active.  Not emitted by KDE 6.x for
     DPMS-only idle without a lock; the Wayland path handles that case.

  4. logind IdleHint PropertiesChanged (system bus)
     Fires when the logind session IdleHint transitions True -> False,
     indicating the session resumed from idle.  Reliable on X11 sessions
     and compositors that report idle state to logind.  Not used by
     KDE 6.x on Wayland (IdleHint never transitions in that configuration).

  5. logind PrepareForSleep (system bus)
     Fires with argument False when the system resumes from suspend.
     Covers the case where the system suspends during an idle period,
     bypassing the normal idle -> resume event sequence.

Runtime dependencies
--------------------
    python3-pywayland - Wayland protocol bindings (sources 1, 2)
    python3-dbus      - DBus signal subscription  (sources 3-5)
    python3-gobject   - GLib main loop for DBus   (sources 3-5)
    cec-utils         - provides /usr/bin/cec-client

sd_notify is implemented inline; no python3-sdnotify dependency required.

Configuration
-------------
All options have corresponding CEC_WAKE_* environment variables so the
daemon can be configured via an EnvironmentFile without touching the
service unit.

    # ~/.config/cec-wake/cec-wake.conf
    CEC_WAKE_HDMI_PORT=3
    CEC_WAKE_IDLE_TIMEOUT=60
    CEC_WAKE_OSD_NAME=MyPC
    CEC_WAKE_DEBUG=0
    # CEC_WAKE_ADAPTER=/dev/cec
    # CEC_WAKE_DEVICE_TIMEOUT=120
    # CEC_WAKE_WAKE_ON_START=0
    # CEC_WAKE_NO_WAYLAND=0
    # CEC_WAKE_NO_DBUS=0

systemd unit requirements
--------------------------
WAYLAND_DISPLAY is not inherited by user services automatically.  Add:
    Environment=WAYLAND_DISPLAY=wayland-0
or set it in the EnvironmentFile.

Logind session path encoding
-----------------------------
The logind object path for a session is derived from XDG_SESSION_ID by
replacing each character outside [A-Za-z0-9_] with '_' followed by its
two-hex-digit ASCII value.  For numeric IDs (the common case) this yields
/org/freedesktop/login1/session/_3<digits> (e.g. session "2" -> "_32").
"""

import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from argparse import ArgumentParser, RawDescriptionHelpFormatter

try:
    from pywayland.client import Display as WaylandDisplay
    from pywayland.protocol.ext_idle_notify_v1 import ExtIdleNotifierV1
    from pywayland.protocol.wayland import WlSeat
except ImportError:
    print("Please install python3-pywayland", file=sys.stderr)
    raise

# zwlr_output_power_management_unstable_v1 is not yet advertised by KWin 6.x
# but is included for forward compatibility.  Import failure is non-fatal.
try:
    from pywayland.protocol.wlr_output_power_management_unstable_v1 import (
        ZwlrOutputPowerManagerV1,
    )
    HAVE_WLR_OUTPUT_POWER = True
except ImportError:
    HAVE_WLR_OUTPUT_POWER = False

# DBus signal support requires python3-dbus and python3-gobject.
# Non-fatal; daemon operates on Wayland sources alone if unavailable.
try:
    import dbus
    import dbus.mainloop.glib
    from gi.repository import GLib
    HAVE_DBUS = True
except ImportError:
    HAVE_DBUS = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CEC_CLIENT = "/usr/bin/cec-client"

CEC_WAKE_CMD = b"on 0\nquit\n"
CEC_SELECT_CMD = b"as\nquit\n"

# Seconds between Wayland reconnect attempts after unexpected disconnect.
WAYLAND_RECONNECT_DELAY_SEC = 5

# zwlr_output_power_management_v1 mode values (from protocol XML).
WLR_OUTPUT_POWER_MODE_OFF = 0
WLR_OUTPUT_POWER_MODE_ON = 1

LOG = logging.getLogger("cec-wake")

# ---------------------------------------------------------------------------
# DBus constants
# ---------------------------------------------------------------------------

# Screensaver interfaces monitored on the session bus.
# Covers lock-based wake events across common desktop environments.
# Not emitted by KDE 6.x for DPMS-only idle; Wayland path handles that case.
SCREENSAVER_INTERFACES = [
    "org.freedesktop.ScreenSaver",
    "org.kde.screensaver",
    "org.gnome.ScreenSaver",
    "org.cinnamon.ScreenSaver",
]

LOGIND_BUS_NAME       = "org.freedesktop.login1"
LOGIND_MANAGER_PATH   = "/org/freedesktop/login1"
LOGIND_MANAGER_IFACE  = "org.freedesktop.login1.Manager"
LOGIND_SESSION_IFACE  = "org.freedesktop.login1.Session"
DBUS_PROPS_IFACE      = "org.freedesktop.DBus.Properties"

# Resume delay after system suspend to allow display and CEC adapter
# re-initialisation before sending commands.
SUSPEND_RESUME_DELAY_SEC = 3

# ---------------------------------------------------------------------------
# systemd sd_notify (inline; avoids python3-sdnotify dependency)
# ---------------------------------------------------------------------------


def sd_notify(msg: str) -> None:
    """
    Send a sd_notify message to systemd over NOTIFY_SOCKET.

    No-op if NOTIFY_SOCKET is not set.  Errors are silently ignored; a
    failed notification is not worth crashing the daemon over.
    """
    notify_socket = os.getenv("NOTIFY_SOCKET")
    if not notify_socket:
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        with sock:
            sock.connect(notify_socket)
            sock.sendall(msg.encode())
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------


def wait_for_device(adapter_path: str, timeout: int = 120) -> None:
    """
    Block until the CEC device node exists and is writable, or raise
    RuntimeError on timeout.

    Raises instead of calling sys.exit() so the caller controls shutdown
    and can send STOPPING=1 to systemd before exiting.
    """
    LOG.info("Waiting for CEC device %s (timeout %ds)...", adapter_path, timeout)
    end_time = time.monotonic() + timeout
    while True:
        if os.path.exists(adapter_path):
            if os.access(adapter_path, os.W_OK):
                LOG.info("Found writable CEC device: %s", adapter_path)
                return
            LOG.error("CEC device %s exists but is not writable", adapter_path)
            LOG.error(
                "Ensure the service runs as the logged-in user (not root) and "
                "the udev rule is present: udevadm info %s",
                adapter_path,
            )
            raise RuntimeError(f"No write access to {adapter_path}")
        if time.monotonic() > end_time:
            raise RuntimeError(f"CEC device {adapter_path} not found after {timeout}s")
        time.sleep(1)


# ---------------------------------------------------------------------------
# CEC commands
# ---------------------------------------------------------------------------


def _run_cec_cmd(cmd: list, cec_input: bytes, label: str) -> bool:
    """
    Run cec-client with the given stdin payload and return True on success.

    Must be called from a worker thread, not the Wayland event loop thread.
    On timeout the entire process group is SIGKILL'd to release the USB
    CEC adapter before returning.
    """
    LOG.info("Sending CEC %s command", label)
    LOG.debug("Command: %s  stdin: %s", cmd, cec_input)
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(input=cec_input, timeout=10)
        except subprocess.TimeoutExpired:
            LOG.error(
                "cec-client timed out during %s; killing process group", label
            )
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return False

        if proc.returncode != 0:
            LOG.warning(
                "cec-client exited %d during %s: %s",
                proc.returncode,
                label,
                stderr.decode(errors="replace").strip(),
            )
            return False

        LOG.debug(
            "cec-client %s output: %s", label, stdout.decode(errors="replace").strip()
        )
        return True

    except OSError as exc:
        LOG.error("Failed to run cec-client during %s: %s", label, exc)
        return False


def run_cec_wake(hdmi_port: int = 0, osd_name: str = "") -> None:
    """
    Send Power-On then Active-Source CEC commands via cec-client.

    Must be called from a dedicated thread, NOT the Wayland event loop
    thread.  cec-client can block inside libcec's USB adapter open path;
    blocking the event loop prevents Wayland keepalives from being sent,
    which can cause the compositor to drop the connection.

    No explicit adapter path is passed to cec-client; libcec auto-detects
    the Pulse-Eight USB adapter via USB enumeration.  An explicit path would
    be treated as a serial port, which fails on USB character devices.
    """
    cmd = [CEC_CLIENT, "-s"]
    if hdmi_port:
        cmd += ["-p", str(hdmi_port)]
    if osd_name:
        cmd += ["-o", osd_name]

    if not _run_cec_cmd(cmd, CEC_WAKE_CMD, "Power-On"):
        return
    _run_cec_cmd(cmd, CEC_SELECT_CMD, "Active-Source")


# ---------------------------------------------------------------------------
# Wake dispatcher
# ---------------------------------------------------------------------------


def build_wake_dispatcher(hdmi_port: int = 0, osd_name: str = ""):
    """
    Return a callable that dispatches a CEC wake in a daemon thread.

    A single non-blocking Lock is shared across all Wayland event sources
    so only one cec-client invocation runs at a time.  Events arriving
    while a wake is in flight are silently dropped; the in-flight call
    already sent the command.
    """
    _lock = threading.Lock()

    def _wake_thread(source: str):
        try:
            run_cec_wake(hdmi_port, osd_name)
        finally:
            _lock.release()

    def dispatch(source: str) -> None:
        if not _lock.acquire(blocking=False):
            LOG.debug("Wake skipped (%s): cec-client already running", source)
            return
        LOG.info("Wake triggered by %s, sending CEC commands", source)
        threading.Thread(
            target=_wake_thread,
            args=(source,),
            daemon=True,
            name="cec-wake",
        ).start()

    return dispatch


# ---------------------------------------------------------------------------
# Wayland protocol handlers
# ---------------------------------------------------------------------------


def _setup_idle_notify(globals_, idle_timeout_msec: int, dispatch) -> bool:
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

    def on_idled(notification):
        LOG.debug("ext-idle-notify: idled")

    def on_resumed(notification):
        LOG.debug("ext-idle-notify: resumed")
        dispatch("ext-idle-notify-v1:resumed")

    notification.dispatcher["idled"] = on_idled
    notification.dispatcher["resumed"] = on_resumed

    LOG.info("Subscribed to ext-idle-notify-v1 (timeout %dms)", idle_timeout_msec)
    return True


def _setup_output_power(globals_, dispatch) -> bool:
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


def _bind_output_power(manager, output, dispatch) -> None:
    """
    Bind a zwlr_output_power_v1 object for a single wl_output and register
    a mode change handler.

    Calls dispatch() when an output transitions from off to on, indicating
    the display has been powered back on.
    """
    power = manager.get_output_power(output)
    prev_mode = {"value": None}

    def on_mode(power, mode):
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

    def on_failed(power):
        LOG.warning(
            "zwlr-output-power: output power management unavailable for this output"
        )

    power.dispatcher["mode"] = on_mode
    power.dispatcher["failed"] = on_failed


# ---------------------------------------------------------------------------
# Wayland event loop
# ---------------------------------------------------------------------------


def run_wayland_loop(dispatch, idle_timeout_msec: int) -> None:
    """
    Connect to the Wayland compositor and monitor for display wake events.

    Reconnects automatically on compositor disconnect.  Runs until the
    process exits.
    """
    wayland_display = os.getenv("WAYLAND_DISPLAY")
    if not wayland_display:
        LOG.error(
            "WAYLAND_DISPLAY is not set. "
            "Add 'Environment=WAYLAND_DISPLAY=wayland-0' to the systemd "
            "service unit or EnvironmentFile."
        )
        return

    while True:
        _run_wayland_connection(dispatch, idle_timeout_msec, wayland_display)
        LOG.info("Reconnecting in %ds...", WAYLAND_RECONNECT_DELAY_SEC)
        time.sleep(WAYLAND_RECONNECT_DELAY_SEC)


def _run_wayland_connection(
    dispatch, idle_timeout_msec: int, wayland_display: str
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
        LOG.error("Cannot connect to Wayland display %s: %s", wayland_display, exc)
        return

    try:
        _bind_and_run(display, dispatch, idle_timeout_msec)
    except Exception as exc:
        LOG.warning("Wayland connection error: %s", exc)
    finally:
        display.disconnect()


def _bind_and_run(display, dispatch, idle_timeout_msec: int) -> None:
    """
    Discover available protocols, bind handlers, and run the event loop.
    """
    registry = display.get_registry()
    globals_ = {}

    def on_global(registry, name, interface, version):
        if interface == "ext_idle_notifier_v1":
            globals_["idle_notifier"] = registry.bind(
                name, ExtIdleNotifierV1, version
            )
        elif interface == "wl_seat":
            globals_["seat"] = registry.bind(name, WlSeat, version)
        elif interface == "wl_output":
            from pywayland.protocol.wayland import WlOutput
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
            "Ensure KWin is running and WAYLAND_DISPLAY is correct."
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


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------


def setup_watchdog() -> None:
    """
    If systemd watchdog is enabled, start a thread that sends WATCHDOG=1
    at half the configured interval.

    Uses a plain thread rather than GLib.timeout_add; the daemon has no
    GLib dependency.
    """
    watchdog_usec = os.getenv("WATCHDOG_USEC")
    if not watchdog_usec:
        return

    interval_sec = int(watchdog_usec) / 2_000_000
    LOG.info("Systemd watchdog enabled (ping interval %.1fs)", interval_sec)

    def _ping_loop():
        while True:
            time.sleep(interval_sec)
            sd_notify("WATCHDOG=1")

    threading.Thread(
        target=_ping_loop,
        daemon=True,
        name="watchdog",
    ).start()


# ---------------------------------------------------------------------------
# DBus signal sources (logind + screensaver)
# ---------------------------------------------------------------------------


def _logind_session_path() -> str:
    """
    Return the D-Bus object path for the current logind session.

    Logind encodes the session ID into the path by replacing each character
    outside [A-Za-z0-9_] with '_' followed by its two-hex-digit ASCII value.

    Raises RuntimeError if XDG_SESSION_ID is not set.
    """
    session_id = os.getenv("XDG_SESSION_ID")
    if not session_id:
        raise RuntimeError(
            "XDG_SESSION_ID is not set; logind session monitoring unavailable."
        )

    encoded = ""
    for ch in session_id:
        if ch.isalnum() or ch == "_":
            encoded += ch
        else:
            encoded += f"_{ord(ch):02x}"

    return f"/org/freedesktop/login1/session/{encoded}"


def run_dbus_loop(dispatch) -> None:
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


def _subscribe_screensaver(session_bus, dispatch) -> None:
    """
    Register ActiveChanged and SessionIdleChanged receivers for all known
    screensaver interfaces on the session bus.

    add_signal_receiver() is a local registration that cannot fail for a
    missing remote service; all interfaces are always registered.
    """
    def make_active_handler(iface):
        def handler(is_active):
            LOG.debug("ActiveChanged: is_active=%s iface=%s", is_active, iface)
            if not is_active:
                dispatch(f"{iface}:ActiveChanged")
        return handler

    def make_idle_handler(iface):
        def handler(is_idle):
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


def _subscribe_logind_idle(system_bus, dispatch) -> None:
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

    prev_idle = {"value": None}

    try:
        obj = system_bus.get_object(LOGIND_BUS_NAME, session_path)
        props = dbus.Interface(obj, DBUS_PROPS_IFACE)
        prev_idle["value"] = bool(props.Get(LOGIND_SESSION_IFACE, "IdleHint"))
        LOG.debug("Initial logind IdleHint: %s", prev_idle["value"])
    except dbus.DBusException as exc:
        LOG.warning("Could not read initial IdleHint: %s", exc)

    def on_properties_changed(iface, changed, invalidated):
        if iface != LOGIND_SESSION_IFACE:
            return
        if "IdleHint" not in changed:
            return
        idle_now = bool(changed["IdleHint"])
        LOG.debug("logind IdleHint: %s -> %s", prev_idle["value"], idle_now)
        if prev_idle["value"] is True and not idle_now:
            dispatch("logind:IdleHint")
        prev_idle["value"] = idle_now

    system_bus.add_signal_receiver(
        on_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface=DBUS_PROPS_IFACE,
        bus_name=LOGIND_BUS_NAME,
        path=session_path,
    )
    LOG.debug("Subscribed to logind IdleHint on %s", session_path)


def _subscribe_prepare_for_sleep(system_bus, dispatch) -> None:
    """
    Subscribe to logind PrepareForSleep to detect system resume from suspend.

    PrepareForSleep(True)  = system is about to suspend (no action)
    PrepareForSleep(False) = system has resumed from suspend

    A short delay is inserted on resume to allow display and CEC adapter
    re-initialisation before sending commands.
    """
    def on_prepare_for_sleep(sleeping):
        if sleeping:
            return
        LOG.debug("logind: PrepareForSleep(False) - system resuming from suspend")

        def _delayed_dispatch():
            time.sleep(SUSPEND_RESUME_DELAY_SEC)
            dispatch("logind:PrepareForSleep")

        threading.Thread(
            target=_delayed_dispatch,
            daemon=True,
            name="cec-resume-delay",
        ).start()

    system_bus.add_signal_receiver(
        on_prepare_for_sleep,
        signal_name="PrepareForSleep",
        dbus_interface=LOGIND_MANAGER_IFACE,
        bus_name=LOGIND_BUS_NAME,
        path=LOGIND_MANAGER_PATH,
    )
    LOG.debug("Subscribed to logind PrepareForSleep")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args():
    """
    Parse arguments, with environment variables as defaults.

    CLI arguments always take precedence over environment variables.
    """

    def _bool_env(key: str) -> bool:
        v = os.getenv(key, "").strip().lower()
        return v in ("1", "true", "yes")

    parser = ArgumentParser(
        description=__doc__,
        formatter_class=RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=_bool_env("CEC_WAKE_DEBUG"),
        help="Enable debug logging [env: CEC_WAKE_DEBUG]",
    )
    parser.add_argument(
        "--adapter",
        default=os.getenv("CEC_WAKE_ADAPTER", "/dev/cec"),
        metavar="PATH",
        help=(
            "CEC device path to check for at startup (default: /dev/cec). "
            "Not passed to cec-client; libcec auto-detects the adapter "
            "[env: CEC_WAKE_ADAPTER]"
        ),
    )
    parser.add_argument(
        "--device-timeout",
        type=int,
        default=int(os.getenv("CEC_WAKE_DEVICE_TIMEOUT", "120")),
        metavar="SECONDS",
        help=(
            "Seconds to wait for CEC device at startup (default: 120) "
            "[env: CEC_WAKE_DEVICE_TIMEOUT]"
        ),
    )
    parser.add_argument(
        "--hdmi-port",
        type=int,
        default=int(os.getenv("CEC_WAKE_HDMI_PORT", "0")),
        metavar="N",
        help=(
            "HDMI port number the PC is connected to (1-15). "
            "Sets the CEC physical address via cec-client -p, bypassing "
            "DRM-based auto-detection which can fail on nvidia systems when "
            "the GPU enumerates as card1 rather than card0. "
            "If 0, libcec auto-detects (default: 0) [env: CEC_WAKE_HDMI_PORT]"
        ),
    )
    parser.add_argument(
        "--idle-timeout-sec",
        type=int,
        default=int(os.getenv("CEC_WAKE_IDLE_TIMEOUT", "60")),
        metavar="SECONDS",
        help=(
            "Idle timeout for ext-idle-notify-v1, in seconds (default: 60). "
            "Must be less than the KDE display power-off setting so that the "
            "idled event fires before the screen goes dark, arming the "
            "notification for resumed on wake.  Spurious wakes cannot occur "
            "because the notification resets after each resumed event. "
            "[env: CEC_WAKE_IDLE_TIMEOUT]"
        ),
    )
    parser.add_argument(
        "--osd-name",
        default=os.getenv("CEC_WAKE_OSD_NAME", ""),
        metavar="NAME",
        help=(
            "OSD name broadcast to the TV via CEC SetOSDName (max 14 chars, "
            "ASCII printable).  Purely cosmetic; omit to use libcec's default "
            "[env: CEC_WAKE_OSD_NAME]"
        ),
    )
    parser.add_argument(
        "--wake-on-start",
        action="store_true",
        default=_bool_env("CEC_WAKE_WAKE_ON_START"),
        help=(
            "Send a CEC wake command shortly after startup "
            "[env: CEC_WAKE_WAKE_ON_START]"
        ),
    )
    parser.add_argument(
        "--no-wayland",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_WAYLAND"),
        help=(
            "Disable Wayland event sources (ext-idle-notify-v1, "
            "zwlr-output-power-management-v1). "
            "Use on X11 sessions or if Wayland monitoring causes issues "
            "[env: CEC_WAKE_NO_WAYLAND]"
        ),
    )
    parser.add_argument(
        "--no-dbus",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_DBUS"),
        help=(
            "Disable DBus event sources (screensaver, logind IdleHint, "
            "PrepareForSleep). "
            "Use if DBus monitoring causes spurious wakes "
            "[env: CEC_WAKE_NO_DBUS]"
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    if not os.path.exists(CEC_CLIENT):
        print(
            f"cec-client not found at {CEC_CLIENT}; please install cec-utils",
            file=sys.stderr,
        )
        sys.exit(1)

    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "Starting cec-wake-daemon (adapter=%s, hdmi-port=%s, osd-name=%s, "
        "idle-timeout=%ds, wayland=%s, dbus=%s, wlr-output-power=%s)",
        args.adapter,
        args.hdmi_port or "auto",
        args.osd_name or "(libcec default)",
        args.idle_timeout_sec,
        "disabled" if args.no_wayland else "enabled",
        "disabled" if args.no_dbus else "enabled",
        "available" if HAVE_WLR_OUTPUT_POWER else "not in pywayland (will activate if KDE adds support)",
    )

    try:
        wait_for_device(args.adapter, args.device_timeout)
    except RuntimeError as exc:
        LOG.error("%s", exc)
        sd_notify("STOPPING=1")
        sys.exit(1)

    dispatch = build_wake_dispatcher(args.hdmi_port, args.osd_name)

    if not args.no_wayland:
        threading.Thread(
            target=run_wayland_loop,
            args=(dispatch, args.idle_timeout_sec * 1000),
            daemon=True,
            name="wayland-loop",
        ).start()

    if not args.no_dbus:
        threading.Thread(
            target=run_dbus_loop,
            args=(dispatch,),
            daemon=True,
            name="dbus-loop",
        ).start()

    setup_watchdog()
    sd_notify("READY=1")

    if args.wake_on_start:
        LOG.info("Sending initial CEC wake (--wake-on-start)")
        threading.Thread(
            target=run_cec_wake,
            args=(args.hdmi_port, args.osd_name),
            daemon=True,
            name="cec-wake-init",
        ).start()

    stop = threading.Event()

    def on_sigterm(_signum, _frame):
        LOG.info("Received SIGTERM, shutting down")
        stop.set()

    signal.signal(signal.SIGTERM, on_sigterm)

    try:
        stop.wait()
    except KeyboardInterrupt:
        LOG.info("Interrupted, exiting")
    finally:
        sd_notify("STOPPING=1")


if __name__ == "__main__":
    main()
