"""Daemon entry point and wiring."""

from __future__ import annotations

import logging
import signal
import sys
import threading
from pathlib import Path
from types import FrameType

from cec_wake.cec import CEC_CLIENT, run_cec_wake
from cec_wake.config import Config, parse_args
from cec_wake.dbus_sources import run_dbus_loop
from cec_wake.device import wait_for_device
from cec_wake.dispatcher import build_wake_dispatcher
from cec_wake.sd_notify import sd_notify
from cec_wake.threads import spawn_daemon_thread
from cec_wake.watchdog import setup_watchdog
from cec_wake.wayland import HAVE_WLR_OUTPUT_POWER, run_wayland_loop

LOG = logging.getLogger("cec-wake")

__all__ = ["main"]


def _log_startup(config: Config) -> None:
    LOG.info(
        "Starting cec-wake-daemon (adapter=%s, hdmi-port=%s, osd-name=%s, "
        "idle-timeout=%ds, wayland=%s, dbus=%s, wlr-output-power=%s)",
        config.adapter,
        config.hdmi_port or "auto",
        config.osd_name or "(libcec default)",
        config.idle_timeout_sec,
        "disabled" if config.no_wayland else "enabled",
        "disabled" if config.no_dbus else "enabled",
        "available"
        if HAVE_WLR_OUTPUT_POWER
        else "not in pywayland (will activate if KDE adds support)",
    )


def main(stop: threading.Event | None = None) -> None:
    """
    Run the daemon until SIGTERM or ``stop`` is set.

    ``stop`` is accepted as a parameter (rather than only ever created
    internally) so tests can inject an ``Event`` that is already set,
    letting ``main()`` reach ``READY=1`` and return without patching
    process-wide state such as ``threading.Event``.
    """
    if not Path(CEC_CLIENT).exists():
        print(
            f"cec-client not found at {CEC_CLIENT}; please install cec-utils",
            file=sys.stderr,
        )
        sys.exit(1)

    config = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if config.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    _log_startup(config)

    try:
        wait_for_device(config.adapter, config.device_timeout)
    except RuntimeError as exc:
        LOG.error("%s", exc)  # noqa: TRY400 - failure is surfaced via sys.exit.
        sd_notify("STOPPING=1")
        sys.exit(1)

    dispatch = build_wake_dispatcher(config.hdmi_port, config.osd_name)

    if not config.no_wayland:
        spawn_daemon_thread(
            run_wayland_loop,
            args=(dispatch, config.idle_timeout_sec * 1000),
            name="wayland-loop",
        )

    if not config.no_dbus:
        spawn_daemon_thread(run_dbus_loop, args=(dispatch,), name="dbus-loop")

    setup_watchdog()
    sd_notify("READY=1")

    if config.wake_on_start:
        LOG.info("Sending initial CEC wake (--wake-on-start)")
        spawn_daemon_thread(
            run_cec_wake,
            args=(config.hdmi_port, config.osd_name),
            name="cec-wake-init",
        )

    if stop is None:
        stop = threading.Event()

    def on_sigterm(_signum: int, _frame: FrameType | None) -> None:
        LOG.info("Received SIGTERM, shutting down")
        stop.set()

    signal.signal(signal.SIGTERM, on_sigterm)

    try:
        stop.wait()
    except KeyboardInterrupt:
        LOG.info("Interrupted, exiting")
    finally:
        sd_notify("STOPPING=1")
