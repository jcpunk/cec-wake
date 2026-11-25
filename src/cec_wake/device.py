"""CEC device readiness check."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

LOG = logging.getLogger("cec-wake")

__all__ = ["wait_for_device"]


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
        if Path(adapter_path).exists():
            if os.access(adapter_path, os.W_OK):
                LOG.info("Found writable CEC device: %s", adapter_path)
                return
            LOG.error("CEC device %s exists but is not writable", adapter_path)
            LOG.error(
                "Ensure the service runs as the logged-in user (not root) and "
                "the udev rule is present: udevadm info %s",
                adapter_path,
            )
            raise RuntimeError(f"No write access to {adapter_path}")  # noqa: TRY003
        if time.monotonic() > end_time:
            raise RuntimeError(  # noqa: TRY003
                f"CEC device {adapter_path} not found after {timeout}s"
            )
        time.sleep(1)
