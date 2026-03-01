#!/usr/bin/python3
"""
cec_wake_daemon.py - HDMI-CEC wake controller for Linux desktops

Listens for display-wake events from complementary sources and sends
a CEC Active Source command when the screen comes back on:

  1. Wayland: ext-idle-notify-v1 protocol via python3-pywayland.
     This is the primary path for KDE 6.x on Wayland, where DPMS-off-only
     idle (no screen lock) is managed entirely inside KWin with no DBus
     surface.  The idle notification timeout is auto-detected from
     ~/.config/powerdevilrc (TurnOffDisplayIdleTimeoutSec minus 5s).
     --idle-timeout-sec overrides auto-detection when needed.

  2. Session DBus: screensaver ActiveChanged signals (screen lock/unlock).
     Covers GNOME, Cinnamon, and KDE when the screen is actually locked.

  3. System DBus: org.freedesktop.login1.Session PropertiesChanged on
     IdleHint (True -> False transition).  Retained as a fallback for
     non-Wayland sessions or compositors that do report idle to logind.
     Not used by KDE 6.x on Wayland (IdleHint never transitions).

All sources share a single non-blocking lock so only one cec-client
invocation runs at a time regardless of which source fires first.

Runtime dependencies:
    python3-pywayland   - ext-idle-notify-v1 Wayland protocol support
    python3-dbus        (dbus-python)   - session + system bus subscription
    python3-gobject     (pygobject3)    - GLib main loop
    cec-utils                           - provides /usr/bin/cec-client

sd_notify is implemented inline; no python3-sdnotify dependency required.

Logind session path encoding
-----------------------------
The logind object path for a session is derived from XDG_SESSION_ID by
replacing each character that is not [A-Za-z0-9_] with '_' followed by
its two-hex-digit ASCII value.  For numeric IDs (the common case) this
yields /org/freedesktop/login1/session/_3<digits> where _3 is the
encoding of the ASCII digit range (e.g. session "2" -> "_32").
"""

import configparser
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
    import dbus
    import dbus.mainloop.glib
except ImportError:
    print("Please install python3-dbus (dbus-python)", file=sys.stderr)
    raise

try:
    from gi.repository import GLib
except ImportError:
    print("Please install python3-gobject (pygobject3)", file=sys.stderr)
    raise

try:
    from pywayland.client import Display as WaylandDisplay
    from pywayland.protocol.ext_idle_notify_v1 import ExtIdleNotifierV1
    from pywayland.protocol.wayland import WlSeat

    HAVE_PYWAYLAND = True
except ImportError:
    HAVE_PYWAYLAND = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CEC_CLIENT = "/usr/bin/cec-client"

CEC_WAKE_CMD = b"on 0\nquit\n"
CEC_SELECT_CMD = b"as\nquit\n"

# Screensaver DBus interfaces (session bus).
# Covers lock-based wake events; not used for DPMS-only idle on KDE/Wayland.
SCREENSAVER_INTERFACES = [
    "org.freedesktop.ScreenSaver",
    "org.kde.screensaver",
    "org.gnome.ScreenSaver",
    "org.cinnamon.ScreenSaver",
]

LOGIND_BUS_NAME = "org.freedesktop.login1"
LOGIND_SESSION_IFACE = "org.freedesktop.login1.Session"
DBUS_PROPS_IFACE = "org.freedesktop.DBus.Properties"

# Wayland event loop reconnect delay on unexpected disconnect.
WAYLAND_RECONNECT_DELAY_SEC = 5

LOG = logging.getLogger("cec-wake")

# ---------------------------------------------------------------------------
# systemd sd_notify (inline; avoids python3-sdnotify dependency)
# ---------------------------------------------------------------------------


def sd_notify(msg: str) -> None:
    """
    Send a sd_notify message to systemd over NOTIFY_SOCKET.

    No-op if NOTIFY_SOCKET is not set (not running under systemd, or
    NotifyAccess not configured).  Errors are silently ignored; a failed
    notification is not worth crashing the daemon over.
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


def logind_session_path() -> str:
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


# ---------------------------------------------------------------------------
# KDE power management config
# ---------------------------------------------------------------------------


def kde_screen_off_timeout_sec() -> int | None:
    """
    Read the display-off idle timeout from KDE Plasma 6's powerdevilrc.

    Plasma 6 stores power settings in ~/.config/powerdevilrc using a nested
    section syntax (e.g. [AC][Display]) that configparser reads as a flat
    key "AC][Display" due to the literal bracket characters in the name.

    Returns the AC profile display-off timeout in seconds, or None if the
    file or key is absent.  The locked-screen timeout
    (TurnOffDisplayIdleTimeoutWhenLockedSec) is intentionally ignored; the
    Wayland idle notification fires regardless of lock state and we want
    the longer of the two timeouts to ensure idled always fires before
    the display powers off.

    Falls back gracefully to None so the caller can use --idle-timeout-sec.
    """
    config_path = os.path.join(os.getenv("HOME", ""), ".config", "powerdevilrc")
    if not os.path.exists(config_path):
        return None

    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    try:
        val = cfg.get("AC][Display", "TurnOffDisplayIdleTimeoutSec")
        return int(val)
    except (configparser.Error, ValueError):
        return None


# ---------------------------------------------------------------------------
# CEC command
# ---------------------------------------------------------------------------


def _run_cec_cmd(cmd: list, cec_input: bytes, label: str) -> bool:
    """
    Run cec-client with the given stdin payload and return True on success.

    Must be called from a worker thread, not the GLib main loop thread.
    On timeout the entire process group is SIGKILL'd to release the USB
    CEC adapter.
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
            LOG.error("cec-client timed out during %s; killing process group", label)
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
    Send Power-On then Active Source CEC commands via cec-client.

    Must be called from a dedicated thread, NOT the GLib main loop thread.
    cec-client can hang inside libcec's USB adapter open path; blocking the
    main loop prevents GLib.timeout_add watchdog pings from firing.
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
# DBus signal handling
# ---------------------------------------------------------------------------


def build_wake_dispatcher(hdmi_port: int = 0, osd_name: str = ""):
    """
    Return a callable that dispatches a CEC wake in a daemon thread.

    A single non-blocking Lock is shared across all signal sources so only
    one cec-client invocation runs at a time.  Signals arriving while a
    wake is in flight are silently dropped.
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


def subscribe_screensaver_signals(bus, dispatch) -> list:
    """
    Register ActiveChanged and SessionIdleChanged receivers on the session
    bus for all known screensaver interfaces.

    These cover lock-based and session-idle-based wake events for GNOME,
    Cinnamon, and KDE in configurations where the screen locker is active.
    For KDE 6.x DPMS-only idle on Wayland, subscribe_wayland_idle() is
    the effective path; these registrations are retained as fallbacks.
    """

    def on_active_changed(is_active, sender_interface=None):
        LOG.debug("ActiveChanged: is_active=%s iface=%s", is_active, sender_interface)
        if not is_active:
            dispatch(sender_interface or "screensaver:ActiveChanged")

    def on_session_idle_changed(is_idle, sender_interface=None):
        LOG.debug("SessionIdleChanged: is_idle=%s iface=%s", is_idle, sender_interface)
        if not is_idle:
            dispatch(sender_interface or "screensaver:SessionIdleChanged")

    for iface in SCREENSAVER_INTERFACES:

        def make_active_handler(captured_iface):
            def handler(is_active):
                on_active_changed(is_active, sender_interface=captured_iface)

            return handler

        def make_idle_handler(captured_iface):
            def handler(is_idle):
                on_session_idle_changed(is_idle, sender_interface=captured_iface)

            return handler

        bus.add_signal_receiver(
            make_active_handler(iface),
            signal_name="ActiveChanged",
            dbus_interface=iface,
        )
        bus.add_signal_receiver(
            make_idle_handler(iface),
            signal_name="SessionIdleChanged",
            dbus_interface=iface,
        )
        LOG.debug("Subscribed to %s.ActiveChanged + SessionIdleChanged", iface)

    return SCREENSAVER_INTERFACES


def subscribe_logind_idle(system_bus, session_path: str, dispatch) -> None:
    """
    Subscribe to logind IdleHint PropertiesChanged on the system bus.

    Retained as a fallback for non-Wayland sessions or compositors that do
    report idle state to logind.  On KDE 6.x Wayland, IdleHint never
    transitions (confirmed: IdleSinceHint=0 at all times), so this path
    is a no-op in practice for that configuration.
    """
    _prev_idle = {"value": None}

    def on_properties_changed(iface, changed, invalidated):
        if iface != LOGIND_SESSION_IFACE:
            return
        if "IdleHint" not in changed:
            return
        idle_now = bool(changed["IdleHint"])
        LOG.debug("logind IdleHint: %s -> %s", _prev_idle["value"], idle_now)
        if _prev_idle["value"] is True and not idle_now:
            dispatch("logind:IdleHint")
        _prev_idle["value"] = idle_now

    # Seed the initial state so a restart mid-idle doesn't miss the first
    # True->False transition after the daemon comes back up.
    try:
        obj = system_bus.get_object(LOGIND_BUS_NAME, session_path)
        props = dbus.Interface(obj, DBUS_PROPS_IFACE)
        _prev_idle["value"] = bool(props.Get(LOGIND_SESSION_IFACE, "IdleHint"))
        LOG.debug("Initial logind IdleHint: %s", _prev_idle["value"])
    except dbus.DBusException as exc:
        LOG.warning("Could not read initial IdleHint: %s", exc)

    system_bus.add_signal_receiver(
        on_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface=DBUS_PROPS_IFACE,
        bus_name=LOGIND_BUS_NAME,
        path=session_path,
    )
    LOG.info("Subscribed to logind IdleHint changes on %s", session_path)


# ---------------------------------------------------------------------------
# Wayland idle monitoring (primary path for KDE 6.x on Wayland)
# ---------------------------------------------------------------------------


def subscribe_wayland_idle(dispatch, timeout_msec: int) -> None:
    """
    Subscribe to ext-idle-notify-v1 via python3-pywayland.

    This is the only reliable wake signal for KDE 6.x DPMS-off-only idle
    on Wayland.  KWin manages DPMS entirely inside the compositor; no DBus
    signal is emitted and logind IdleHint never transitions.

    The ext-idle-notify-v1 protocol requires the client to register an idle
    timeout.  KWin only fires the 'idled' event (and therefore the 'resumed'
    event on activity) when the registered timeout <= the compositor's own
    screen-off timeout.  Set --idle-timeout-sec to a value strictly less
    than your KDE display power-off setting.

    Runs a persistent event loop in a daemon thread.  On unexpected
    disconnect (compositor restart, KWin crash), the thread sleeps
    WAYLAND_RECONNECT_DELAY_SEC and reconnects automatically.

    WAYLAND_DISPLAY must be set in the environment.  systemd user services
    do not inherit it automatically; add:
        Environment=WAYLAND_DISPLAY=wayland-0
    or use an EnvironmentFile that sets it, to the service unit.
    """
    if not HAVE_PYWAYLAND:
        LOG.warning(
            "python3-pywayland not available; Wayland idle monitoring disabled. "
            "Install python3-pywayland to support KDE 6.x DPMS-only idle wake."
        )
        return

    wayland_display = os.getenv("WAYLAND_DISPLAY")
    if not wayland_display:
        LOG.warning(
            "WAYLAND_DISPLAY is not set; Wayland idle monitoring disabled. "
            "Add 'Environment=WAYLAND_DISPLAY=wayland-0' to the systemd service unit "
            "or set it in the EnvironmentFile."
        )
        return

    def _run_loop():
        while True:
            display = WaylandDisplay()
            try:
                display.connect()
            except Exception as exc:
                LOG.error(
                    "Cannot connect to Wayland display %s: %s — retrying in %ds",
                    wayland_display,
                    exc,
                    WAYLAND_RECONNECT_DELAY_SEC,
                )
                time.sleep(WAYLAND_RECONNECT_DELAY_SEC)
                continue

            registry = display.get_registry()
            globals_ = {}

            def on_global(registry, name, interface, version):
                if interface == "ext_idle_notifier_v1":
                    globals_["notifier"] = registry.bind(
                        name, ExtIdleNotifierV1, version
                    )
                elif interface == "wl_seat":
                    globals_["seat"] = registry.bind(name, WlSeat, version)

            registry.dispatcher["global"] = on_global

            display.roundtrip()

            notifier = globals_.get("notifier")
            seat = globals_.get("seat")

            if not notifier or not seat:
                LOG.error(
                    "ext_idle_notifier_v1 or wl_seat not advertised by compositor. "
                    "Wayland idle monitoring unavailable."
                )
                display.disconnect()
                return  # No point retrying; compositor doesn't support the protocol.

            notification = notifier.get_idle_notification(timeout_msec, seat)

            def on_idled(notification):
                LOG.debug("Wayland: idled (display powered off)")

            def on_resumed(notification):
                LOG.debug("Wayland: resumed (user activity detected)")
                dispatch("wayland:ext-idle-notify-v1")

            notification.dispatcher["idled"] = on_idled
            notification.dispatcher["resumed"] = on_resumed

            display.roundtrip()
            LOG.info(
                "Subscribed to ext-idle-notify-v1 on %s (timeout %dms)",
                wayland_display,
                timeout_msec,
            )

            try:
                while True:
                    display.flush()
                    if display.dispatch(block=True) == -1:
                        LOG.warning(
                            "Wayland display.dispatch() returned -1; "
                            "reconnecting in %ds",
                            WAYLAND_RECONNECT_DELAY_SEC,
                        )
                        break
            except Exception as exc:
                LOG.warning(
                    "Wayland event loop error: %s; reconnecting in %ds",
                    exc,
                    WAYLAND_RECONNECT_DELAY_SEC,
                )
            finally:
                display.disconnect()

            time.sleep(WAYLAND_RECONNECT_DELAY_SEC)

    threading.Thread(
        target=_run_loop,
        daemon=True,
        name="wayland-idle",
    ).start()


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------


def setup_watchdog() -> None:
    """
    If systemd watchdog is enabled, schedule periodic WATCHDOG=1
    notifications at half the configured interval.
    """
    watchdog_usec = os.getenv("WATCHDOG_USEC")
    if not watchdog_usec:
        return

    interval_sec = int(watchdog_usec) / 2_000_000
    interval_ms = int(interval_sec * 1000)
    LOG.info("Systemd watchdog enabled (ping interval %.1fs)", interval_sec)

    def ping():
        sd_notify("WATCHDOG=1")
        return True

    GLib.timeout_add(interval_ms, ping)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args():
    """
    Parse arguments, with environment variables as defaults.

    Config file format (shell-style key=value):

        # ~/.config/cec-wake/cec-wake.conf
        CEC_WAKE_HDMI_PORT=3
        CEC_WAKE_IDLE_TIMEOUT=0
        CEC_WAKE_WAKE_ON_START=1
        CEC_WAKE_DEBUG=0
        CEC_WAKE_OSD_NAME=MyPC
        # CEC_WAKE_ADAPTER=/dev/cec
        # CEC_WAKE_DEVICE_TIMEOUT=120
        # CEC_WAKE_NO_LOGIND=0
        # CEC_WAKE_NO_WAYLAND=0
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
            "CEC device path to check for at startup (default: /dev/cec) "
            "[env: CEC_WAKE_ADAPTER]"
        ),
    )
    parser.add_argument(
        "--device-timeout",
        type=int,
        default=int(os.getenv("CEC_WAKE_DEVICE_TIMEOUT", "120")),
        metavar="SECONDS",
        help="Seconds to wait for CEC device at startup (default: 120) [env: CEC_WAKE_DEVICE_TIMEOUT]",
    )
    parser.add_argument(
        "--hdmi-port",
        type=int,
        default=int(os.getenv("CEC_WAKE_HDMI_PORT", "0")),
        metavar="N",
        help=(
            "HDMI port number the PC is connected to (1-15). "
            "Bypasses DRM-based auto-detection via cec-client -p. "
            "If 0, libcec auto-detects (default: 0) [env: CEC_WAKE_HDMI_PORT]"
        ),
    )
    parser.add_argument(
        "--idle-timeout-sec",
        type=int,
        default=int(os.getenv("CEC_WAKE_IDLE_TIMEOUT", "0")),
        metavar="SECONDS",
        help=(
            "Override the idle timeout registered with ext-idle-notify-v1, "
            "in seconds.  Normally auto-detected from ~/.config/powerdevilrc "
            "(TurnOffDisplayIdleTimeoutSec minus 5s).  Must be strictly less "
            "than the KDE display power-off timeout or the idled/resumed "
            "events never fire.  Set to 0 to use auto-detection (default). "
            "[env: CEC_WAKE_IDLE_TIMEOUT]"
        ),
    )
    parser.add_argument(
        "--wake-on-start",
        action="store_true",
        default=_bool_env("CEC_WAKE_WAKE_ON_START"),
        help="Send a CEC wake command shortly after startup [env: CEC_WAKE_WAKE_ON_START]",
    )
    parser.add_argument(
        "--osd-name",
        default=os.getenv("CEC_WAKE_OSD_NAME", ""),
        metavar="NAME",
        help=(
            "OSD name broadcast to the TV via CEC SetOSDName (max 14 chars). "
            "Omit to use libcec's default [env: CEC_WAKE_OSD_NAME]"
        ),
    )
    parser.add_argument(
        "--no-logind",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_LOGIND"),
        help=(
            "Disable logind IdleHint monitoring (system bus). "
            "Use if logind causes spurious wakes [env: CEC_WAKE_NO_LOGIND]"
        ),
    )
    parser.add_argument(
        "--no-wayland",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_WAYLAND"),
        help=(
            "Disable Wayland ext-idle-notify-v1 monitoring. "
            "Use if the session is X11 or Wayland monitoring causes issues "
            "[env: CEC_WAKE_NO_WAYLAND]"
        ),
    )
    return parser.parse_args()


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
        "idle-timeout=%s, logind=%s, wayland=%s)",
        args.adapter,
        args.hdmi_port or "auto",
        args.osd_name or "(libcec default)",
        f"{args.idle_timeout_sec}s (override)" if args.idle_timeout_sec else "auto",
        "disabled" if args.no_logind else "enabled",
        "disabled" if args.no_wayland else "enabled",
    )

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    try:
        wait_for_device(args.adapter, args.device_timeout)
    except RuntimeError as exc:
        LOG.error("%s", exc)
        sd_notify("STOPPING=1")
        sys.exit(1)

    try:
        session_bus = dbus.SessionBus()
    except dbus.DBusException as exc:
        LOG.error("Cannot connect to session bus: %s", exc)
        sd_notify("STOPPING=1")
        sys.exit(1)

    dispatch = build_wake_dispatcher(args.hdmi_port, args.osd_name)

    subscribed = subscribe_screensaver_signals(session_bus, dispatch)
    LOG.info("Monitoring screensaver interfaces: %s", subscribed)

    if not args.no_wayland:
        if args.idle_timeout_sec:
            effective_timeout_sec = args.idle_timeout_sec
            LOG.info("Using --idle-timeout-sec override: %ds", effective_timeout_sec)
        else:
            kde_timeout = kde_screen_off_timeout_sec()
            if kde_timeout is not None:
                effective_timeout_sec = max(1, kde_timeout - 5)
                LOG.info(
                    "KDE screen-off timeout: %ds, using idle-notify timeout: %ds",
                    kde_timeout,
                    effective_timeout_sec,
                )
            else:
                LOG.warning(
                    "Could not read KDE screen-off timeout from ~/.config/powerdevilrc; "
                    "set --idle-timeout-sec explicitly or set CEC_WAKE_IDLE_TIMEOUT. "
                    "Wayland idle monitoring disabled."
                )
                effective_timeout_sec = 0

        if effective_timeout_sec:
            subscribe_wayland_idle(dispatch, effective_timeout_sec * 1000)

    if not args.no_logind:
        try:
            session_path = logind_session_path()
            system_bus = dbus.SystemBus()
            subscribe_logind_idle(system_bus, session_path, dispatch)
        except RuntimeError as exc:
            LOG.warning("Logind monitoring unavailable: %s", exc)
        except dbus.DBusException as exc:
            LOG.warning("Cannot connect to system bus for logind monitoring: %s", exc)

    loop = GLib.MainLoop()

    def on_sigterm(_signum, _frame):
        LOG.info("Received SIGTERM, shutting down")
        loop.quit()

    signal.signal(signal.SIGTERM, on_sigterm)

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

    try:
        loop.run()
    except KeyboardInterrupt:
        LOG.info("Interrupted, exiting")
    finally:
        sd_notify("STOPPING=1")


if __name__ == "__main__":
    main()
