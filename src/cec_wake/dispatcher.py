"""Single-flight CEC wake dispatcher shared by every wake-event source."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from cec_wake.cec import run_cec_wake
from cec_wake.threads import spawn_daemon_thread

LOG = logging.getLogger("cec-wake")

__all__ = ["build_wake_dispatcher"]


def build_wake_dispatcher(
    hdmi_port: int = 0, osd_name: str = ""
) -> Callable[[str], None]:
    """
    Return a callable that dispatches a CEC wake in a daemon thread.

    A single non-blocking Lock is shared across all wake-event sources so
    only one cec-client invocation runs at a time.  Events arriving while a
    wake is in flight are silently dropped; the in-flight call already sent
    the command.
    """
    lock = threading.Lock()

    def _wake_thread() -> None:
        try:
            run_cec_wake(hdmi_port, osd_name)
        finally:
            lock.release()

    def dispatch(source: str) -> None:
        if not lock.acquire(blocking=False):
            LOG.debug("Wake skipped (%s): cec-client already running", source)
            return
        LOG.info("Wake triggered by %s, sending CEC commands", source)
        spawn_daemon_thread(_wake_thread, name="cec-wake")

    return dispatch
