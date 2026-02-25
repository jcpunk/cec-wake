#!/usr/bin/python3
"""
cec_wake_daemon.py - HDMI-CEC wake controller for Linux desktops

Listens for display-wake events from two complementary sources and sends
a CEC Active Source command when the screen comes back on:

  1. Session DBus: screensaver ActiveChanged signals (screen lock/unlock).
     Covers GNOME, Cinnamon, and KDE when the screen is actually locked.

  2. System DBus: org.freedesktop.login1.Session PropertiesChanged on
     IdleHint (True -> False transition).  This is the reliable signal for
     KDE 6.x display-power-off-only idle (DPMS off without a screen lock),
     where none of the screensaver interfaces emit anything.

Both sources share a single non-blocking lock so only one cec-client
invocation runs at a time regardless of which source fires first.

Runtime dependencies:
    python3-dbus       (dbus-python)   - session + system bus subscription
    python3-gobject    (pygobject3)    - GLib main loop
    cec-utils                          - provides /usr/bin/cec-client

sd_notify is implemented inline; no python3-sdnotify dependency required.

Logind session path encoding
-----------------------------
The logind object path for a session is derived from XDG_SESSION_ID by
replacing each character that is not [A-Za-z0-9_] with its ASCII value
prefixed with '_'.  For numeric IDs (the common case) this yields
/org/freedesktop/login1/session/_3<digits> where _3 is the encoding of
the ASCII digit range (e.g. session "2" -> "_32", "12" -> "_31_32").
loginctl show-session $XDG_SESSION_ID -p Id can be used to verify.
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CEC_CLIENT = "/usr/bin/cec-client"

CEC_WAKE_CMD = b"on 0\nquit\n"
CEC_SELECT_CMD = b"as\nquit\n"

# Screensaver DBus interfaces to monitor (session bus).
# Covers screen-lock-based wake events across common desktop environments.
# KDE 6.x display-power-off-only idle is handled separately via logind.
SCREENSAVER_INTERFACES = [
    "org.freedesktop.ScreenSaver",
    "org.kde.screensaver",
    "org.gnome.ScreenSaver",
    "org.cinnamon.ScreenSaver",
]

LOGIND_BUS_NAME = "org.freedesktop.login1"
LOGIND_SESSION_IFACE = "org.freedesktop.login1.Session"
DBUS_PROPS_IFACE = "org.freedesktop.DBus.Properties"

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

    /dev/cec is a symlink on Fedora; os.path.exists() follows it correctly.
    os.access() honours effective uid/gid for the permission check.

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
                "The Pulse-Eight adapter uses udev uaccess/seat tags; access is granted "
                "to the active seat user automatically by systemd-logind. "
                "Ensure the service runs as the logged-in user (not root) and the udev "
                "rule is present: udevadm info %s",
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
    Numeric session IDs (e.g. "2") therefore become "_32" (0x32 = '2').

    XDG_SESSION_ID is set by pam_systemd for every login session; its
    absence means the process is not running inside a logind session and
    logind monitoring cannot be used.

    Raises RuntimeError if XDG_SESSION_ID is not set.
    """
    session_id = os.getenv("XDG_SESSION_ID")
    if not session_id:
        raise RuntimeError(
            "XDG_SESSION_ID is not set; logind session monitoring unavailable. "
            "Ensure the service runs as a user session (not a system service)."
        )

    encoded = ""
    for ch in session_id:
        if ch.isalnum() or ch == "_":
            encoded += ch
        else:
            encoded += f"_{ord(ch):02x}"

    return f"/org/freedesktop/login1/session/{encoded}"


# ---------------------------------------------------------------------------
# CEC command
# ---------------------------------------------------------------------------


def _run_cec_cmd(cmd: list, cec_input: bytes, label: str) -> bool:
    """
    Run cec-client with the given stdin payload and return True on success.

    Extracted from run_cec_wake() to eliminate the duplicated Popen block.
    Must be called from a worker thread, not the GLib main loop thread.

    On timeout the entire process group is SIGKILL'd to release the USB
    CEC adapter before returning, preventing a queued second invocation
    from hanging on the still-held adapter lock.
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
                "cec-client timed out during %s; killing process group to release adapter",
                label,
            )
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass  # already exited between timeout and killpg
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

    No explicit adapter path is passed to cec-client.  On Fedora, /dev/cec
    is a symlink to a raw USB device node (/dev/bus/usb/NNN/NNN).  cec-client
    treats any explicit path argument as a serial port and attempts a serial
    lock on it, which always fails on a USB character device.  Without an
    explicit path, libcec auto-detects the Pulse-Eight USB adapter via USB
    enumeration.

    Must be called from a dedicated thread, NOT from the GLib main loop
    thread.  cec-client can hang inside libcec's USB adapter open path;
    blocking the main loop prevents GLib.timeout_add watchdog pings from
    firing, causing systemd to kill the service.
    """
    # -s = single-command mode (read stdin, execute, exit).
    # No adapter path: let libcec auto-detect via USB enumeration.
    # -p <port>: explicitly sets the HDMI port number, which determines the
    # CEC physical address (port 1 -> 1.0.0.0, port 2 -> 2.0.0.0, etc.).
    # Without -p, libcec detects the physical address from DRM device nodes,
    # which can fail in user services when /dev/dri/card0 does not exist
    # (e.g. nvidia systems where the GPU enumerates as card1).
    # -o <n>: sets the OSD (on-screen display) name broadcast to the TV
    # via the CEC SetOSDName message.  Purely cosmetic; does not affect
    # functionality.  Omitted when empty so libcec uses its built-in default.
    # start_new_session=True gives cec-client its own process group so
    # killpg() terminates it without touching the daemon process.
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

    A single non-blocking Lock is shared across all signal sources
    (screensaver interfaces and logind) so only one cec-client invocation
    runs at a time.  Signals arriving while a wake is in flight are dropped;
    the in-flight call already sent the command.

    Returns (dispatch_fn, lock) so callers can share the lock if needed,
    though dispatch_fn is the only interface callers normally use.
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
    Register ActiveChanged signal receivers on the session bus for all
    known screensaver interfaces.

    add_signal_receiver() is a local registration; it cannot fail for a
    missing remote service.  All interfaces are always registered.
    Returns the interface list for logging.
    """

    def on_active_changed(is_active, sender_interface=None):
        """
        is_active=True  -> screen locking / blanking  (no action)
        is_active=False -> screen unlocking            (trigger wake)
        """
        LOG.debug("ActiveChanged: is_active=%s iface=%s", is_active, sender_interface)
        if not is_active:
            dispatch(sender_interface or "screensaver")

    for iface in SCREENSAVER_INTERFACES:
        # Capture iface in the closure via a default argument.
        def make_handler(captured_iface):
            def handler(is_active):
                on_active_changed(is_active, sender_interface=captured_iface)

            return handler

        bus.add_signal_receiver(
            make_handler(iface),
            signal_name="ActiveChanged",
            dbus_interface=iface,
        )
        LOG.debug("Subscribed to %s.ActiveChanged", iface)

    return SCREENSAVER_INTERFACES


def subscribe_logind_idle(system_bus, session_path: str, dispatch) -> None:
    """
    Subscribe to org.freedesktop.login1.Session PropertiesChanged on the
    system bus to detect display-power-off-only idle wake events.

    KDE 6.x PowerDevil powers the display off via DPMS without activating
    the screensaver or screen lock.  In that case none of the screensaver
    ActiveChanged signals fire on wake.  The logind IdleHint property
    transitions True (idle) -> False (active) when the user provides input,
    which is the reliable signal for this case.

    We ignore the False -> True transition (going idle) because we only
    want to act on wake, not on display power-off.
    """
    # Track the previous IdleHint value so we only act on True->False.
    # Initialised to None so the first PropertiesChanged update sets the
    # baseline without triggering a spurious wake.
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

    system_bus.add_signal_receiver(
        on_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface=DBUS_PROPS_IFACE,
        bus_name=LOGIND_BUS_NAME,
        path=session_path,
    )
    LOG.info("Subscribed to logind IdleHint changes on %s", session_path)


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
        return True  # returning True keeps the GLib timer active

    GLib.timeout_add(interval_ms, ping)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args():
    """
    Parse arguments, with environment variables as defaults.

    Each option has a corresponding CEC_WAKE_* environment variable that
    acts as a default, allowing ~/.config/cec-wake/cec-wake.conf (loaded
    via systemd EnvironmentFile=) to configure the daemon without touching
    the service unit.  CLI arguments always take precedence over env vars.

    Config file format (shell-style key=value, no quoting needed for simple
    values):

        # ~/.config/cec-wake/cec-wake.conf
        CEC_WAKE_HDMI_PORT=3
        CEC_WAKE_WAKE_ON_START=1
        CEC_WAKE_DEBUG=0
        CEC_WAKE_OSD_NAME=MyPC
        # CEC_WAKE_ADAPTER=/dev/cec
        # CEC_WAKE_DEVICE_TIMEOUT=120
        # CEC_WAKE_NO_LOGIND=0
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
            "CEC device path to check for at startup (default: /dev/cec); "
            "not passed to cec-client, which auto-detects the adapter "
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
            "Sets the CEC physical address directly via cec-client -p, "
            "bypassing DRM-based auto-detection which can fail in user "
            "services when /dev/dri/card0 does not exist (e.g. nvidia systems "
            "where the GPU enumerates as card1). "
            "If unset, libcec auto-detects (default: 0, auto-detect) "
            "[env: CEC_WAKE_HDMI_PORT]."
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
            "OSD name broadcast to the TV via CEC SetOSDName (max 14 chars, "
            "ASCII printable).  Purely cosmetic; omit to use libcec's default "
            "[env: CEC_WAKE_OSD_NAME]"
        ),
    )
    parser.add_argument(
        "--no-logind",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_LOGIND"),
        help=(
            "Disable logind IdleHint monitoring (system bus). "
            "Use if logind causes spurious wakes in your environment "
            "[env: CEC_WAKE_NO_LOGIND]"
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
        "Starting cec-wake-daemon (adapter=%s, hdmi-port=%s, osd-name=%s, logind=%s)",
        args.adapter,
        args.hdmi_port or "auto",
        args.osd_name or "(libcec default)",
        "disabled" if args.no_logind else "enabled",
    )

    # GLib main loop integration must be installed before connecting to the bus.
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

    # Dispatch wake-on-start after READY=1 so cec-client latency does not
    # delay service readiness or block the watchdog ping path.
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
