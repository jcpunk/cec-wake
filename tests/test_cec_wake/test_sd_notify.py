"""Tests for the inline systemd sd_notify helper."""

from __future__ import annotations

import socket

from cec_wake import sd_notify as sd_notify_mod


def test_sd_notify_no_socket_is_noop(monkeypatch):
    """Without NOTIFY_SOCKET the notify is a silent no-op."""
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    sd_notify_mod.sd_notify("READY=1")  # must not raise


def test_sd_notify_bad_path_is_silenced(monkeypatch, tmp_path):
    """A socket path that cannot be connected is ignored, not fatal."""
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "no-such-socket"))
    sd_notify_mod.sd_notify("READY=1")  # no exception raised


def test_sd_notify_delivers_message(monkeypatch, tmp_path):
    """The message is sent to the socket named by NOTIFY_SOCKET."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(str(tmp_path / "notify"))
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "notify"))
    sd_notify_mod.sd_notify("READY=1")
    assert sock.recv(1024) == b"READY=1"
