"""Shared helper for the daemon's background threads.

Every wake source and the watchdog run on their own daemon thread so a
crash or block in one (for example cec-client hanging on a USB adapter
open) cannot take down the others or the main thread.  All such threads
share the same shape: fire-and-forget, named for `ps`/journal readability,
and marked daemon so the process exits cleanly on shutdown without an
explicit join.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

__all__ = ["spawn_daemon_thread"]


def spawn_daemon_thread(
    target: Callable[..., None], *, name: str, args: tuple[Any, ...] = ()
) -> threading.Thread:
    """Start and return a named daemon thread running target(*args)."""
    thread = threading.Thread(target=target, args=args, daemon=True, name=name)
    thread.start()
    return thread
