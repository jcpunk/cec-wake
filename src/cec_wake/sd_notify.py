"""systemd sd_notify (inline; avoids a python3-sdnotify dependency)."""

from __future__ import annotations

import os
import socket

__all__ = ["sd_notify"]


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
