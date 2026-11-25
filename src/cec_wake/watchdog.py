"""systemd watchdog keepalive pings."""

from __future__ import annotations

import logging
import os
import time

from cec_wake.sd_notify import sd_notify
from cec_wake.threads import spawn_daemon_thread

LOG = logging.getLogger("cec-wake")

__all__ = ["setup_watchdog"]


def setup_watchdog() -> None:
    """
    If systemd watchdog is enabled, start a thread that sends WATCHDOG=1
    at half the configured interval.

    Uses a plain thread rather than GLib.timeout_add; the daemon has no
    GLib dependency outside the optional DBus sources.
    """
    watchdog_usec = os.getenv("WATCHDOG_USEC")
    if not watchdog_usec:
        return

    interval_sec = int(watchdog_usec) / 2_000_000
    LOG.info("Systemd watchdog enabled (ping interval %.1fs)", interval_sec)

    def _ping_loop() -> None:
        while True:
            time.sleep(interval_sec)
            sd_notify("WATCHDOG=1")

    spawn_daemon_thread(_ping_loop, name="watchdog")
