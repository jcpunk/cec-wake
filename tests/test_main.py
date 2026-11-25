"""Tests for the daemon entry point and wiring."""

import argparse

import pytest
from unittest.mock import Mock

import cec_wake_daemon as cec


class _FakeEvent:
    """An Event whose wait() returns immediately so main() can finish."""

    def wait(self, *_args):
        return False

    def set(self):
        return None

    def is_set(self):
        return False


def _args(**overrides):
    base = dict(
        adapter="/dev/cec",
        device_timeout=120,
        hdmi_port=0,
        osd_name="",
        idle_timeout_sec=60,
        no_wayland=True,
        no_dbus=True,
        wake_on_start=False,
        debug=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_main_missing_client_exits(monkeypatch):
    """A missing cec-client aborts with exit code 1."""
    monkeypatch.setattr(cec.Path, "exists", lambda self: False)
    with pytest.raises(SystemExit) as caught:
        cec.main()
    assert caught.value.code == 1


def test_main_device_wait_failure_exits(monkeypatch):
    """A device that never appears aborts and notifies STOPPING."""

    def boom(_adapter, _timeout):
        raise RuntimeError("device gone")

    monkeypatch.setattr(cec.Path, "exists", lambda self: True)
    monkeypatch.setattr(cec, "parse_args", lambda: _args())
    monkeypatch.setattr(cec, "wait_for_device", boom)
    stopped = []
    monkeypatch.setattr(cec, "sd_notify", stopped.append)

    with pytest.raises(SystemExit) as caught:
        cec.main()
    assert caught.value.code == 1
    assert "STOPPING=1" in stopped


def test_main_reaches_ready(monkeypatch):
    """A happy run signals READY=1 and does not block on the stop event."""
    signalled = []

    def notify(msg):
        signalled.append(msg)

    monkeypatch.setattr(cec.Path, "exists", lambda self: True)
    monkeypatch.setattr(cec, "parse_args", lambda: _args())
    monkeypatch.setattr(cec, "wait_for_device", Mock())
    monkeypatch.setattr(cec, "run_wayland_loop", Mock())
    monkeypatch.setattr(cec, "run_dbus_loop", Mock())
    monkeypatch.setattr(cec, "setup_watchdog", Mock())
    monkeypatch.setattr(cec, "run_cec_wake", Mock())
    monkeypatch.setattr(cec, "sd_notify", notify)
    monkeypatch.setattr(cec.threading, "Event", _FakeEvent)

    cec.main()
    assert "READY=1" in signalled
