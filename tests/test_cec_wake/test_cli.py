"""Tests for the daemon entry point and wiring."""

from __future__ import annotations

import threading
from unittest.mock import Mock

import pytest

from cec_wake import cli
from cec_wake.config import Config


def _already_stopped():
    """An Event that is already set so main() returns without blocking."""
    event = cli.threading.Event()
    event.set()
    return event


def _config(**overrides):
    base = {
        "debug": False,
        "adapter": "/dev/cec",
        "device_timeout": 120,
        "hdmi_port": 0,
        "idle_timeout_sec": 60,
        "osd_name": "",
        "wake_on_start": False,
        "no_wayland": True,
        "no_dbus": True,
    }
    base.update(overrides)
    return Config(**base)


def test_main_missing_client_exits(monkeypatch):
    """A missing cec-client aborts with exit code 1."""
    monkeypatch.setattr(cli.Path, "exists", lambda self: False)
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 1


def test_main_device_wait_failure_exits(monkeypatch):
    """A device that never appears aborts and notifies STOPPING."""

    def boom(_adapter, _timeout):
        raise RuntimeError("device gone")

    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(cli, "parse_args", _config)
    monkeypatch.setattr(cli, "wait_for_device", boom)
    stopped = []
    monkeypatch.setattr(cli, "sd_notify", stopped.append)

    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 1
    assert "STOPPING=1" in stopped


def test_main_reaches_ready(monkeypatch):
    """A happy run signals READY=1 and does not block on the stop event."""
    signalled = []

    def notify(msg):
        signalled.append(msg)

    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(cli, "parse_args", _config)
    monkeypatch.setattr(cli, "wait_for_device", Mock())
    monkeypatch.setattr(cli, "run_wayland_loop", Mock())
    monkeypatch.setattr(cli, "run_dbus_loop", Mock())
    monkeypatch.setattr(cli, "setup_watchdog", Mock())
    monkeypatch.setattr(cli, "run_cec_wake", Mock())
    monkeypatch.setattr(cli, "sd_notify", notify)

    cli.main(stop=_already_stopped())
    assert "READY=1" in signalled


def test_main_starts_wayland_and_dbus_threads(monkeypatch):
    """Wayland and DBus loops are started on their own threads when enabled."""
    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(
        cli, "parse_args", lambda: _config(no_wayland=False, no_dbus=False)
    )
    monkeypatch.setattr(cli, "wait_for_device", Mock())
    monkeypatch.setattr(cli, "run_wayland_loop", Mock())
    monkeypatch.setattr(cli, "run_dbus_loop", Mock())
    monkeypatch.setattr(cli, "setup_watchdog", Mock())
    monkeypatch.setattr(cli, "sd_notify", Mock())

    started_thread_names = []
    real_thread = cli.threading.Thread

    def spy_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        started_thread_names.append(kwargs.get("name"))
        return thread

    monkeypatch.setattr(cli.threading, "Thread", spy_thread)

    cli.main(stop=_already_stopped())

    for thread in threading.enumerate():
        if thread.name in ("wayland-loop", "dbus-loop"):
            thread.join(2)

    assert "wayland-loop" in started_thread_names
    assert "dbus-loop" in started_thread_names


def test_main_wake_on_start_sends_cec_wake(monkeypatch):
    """--wake-on-start fires an initial CEC wake on its own thread."""
    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(cli, "parse_args", lambda: _config(wake_on_start=True))
    monkeypatch.setattr(cli, "wait_for_device", Mock())
    monkeypatch.setattr(cli, "setup_watchdog", Mock())
    monkeypatch.setattr(cli, "sd_notify", Mock())

    wake = Mock()
    monkeypatch.setattr(cli, "run_cec_wake", wake)

    cli.main(stop=_already_stopped())

    for thread in threading.enumerate():
        if thread.name == "cec-wake-init":
            thread.join(2)

    wake.assert_called_once_with(0, "")


def test_on_sigterm_sets_stop_event(monkeypatch):
    """SIGTERM sets the stop event instead of killing the process directly."""
    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(cli, "parse_args", _config)
    monkeypatch.setattr(cli, "wait_for_device", Mock())
    monkeypatch.setattr(cli, "setup_watchdog", Mock())
    monkeypatch.setattr(cli, "sd_notify", Mock())

    captured_handler = {}
    real_signal = cli.signal.signal

    def spy_signal(signum, handler):
        captured_handler["handler"] = handler
        return real_signal(signum, handler)

    monkeypatch.setattr(cli.signal, "signal", spy_signal)

    cli.main(stop=_already_stopped())

    assert "handler" in captured_handler
    captured_handler["handler"](cli.signal.SIGTERM, None)  # must not raise


def test_main_creates_its_own_stop_event_and_waits_for_sigterm(monkeypatch):
    """Without an injected stop event, main() creates one and blocks until SIGTERM."""
    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(cli, "parse_args", _config)
    monkeypatch.setattr(cli, "wait_for_device", Mock())
    monkeypatch.setattr(cli, "setup_watchdog", Mock())
    monkeypatch.setattr(cli, "sd_notify", Mock())

    captured_handler = {}
    real_signal = cli.signal.signal

    def spy_signal(signum, handler):
        captured_handler["handler"] = handler
        return real_signal(signum, handler)

    monkeypatch.setattr(cli.signal, "signal", spy_signal)

    # Deliver SIGTERM to this process from a helper thread shortly after
    # main() starts blocking on stop.wait(), exercising the real signal
    # delivery path end-to-end rather than injecting a pre-set event.
    def _deliver_sigterm():
        import os
        import time

        time.sleep(0.05)
        os.kill(os.getpid(), cli.signal.SIGTERM)

    threading.Thread(target=_deliver_sigterm, daemon=True).start()

    cli.main()  # returns once the real SIGTERM handler sets the stop event

    assert "handler" in captured_handler


def test_main_keyboard_interrupt_is_handled(monkeypatch):
    """A KeyboardInterrupt while waiting is logged, not propagated."""
    monkeypatch.setattr(cli.Path, "exists", lambda self: True)
    monkeypatch.setattr(cli, "parse_args", _config)
    monkeypatch.setattr(cli, "wait_for_device", Mock())
    monkeypatch.setattr(cli, "setup_watchdog", Mock())
    stopped = []
    monkeypatch.setattr(cli, "sd_notify", stopped.append)

    class _RaisingEvent:
        def wait(self, *_args):
            raise KeyboardInterrupt

        def set(self):
            return None

        def is_set(self):
            return False

    cli.main(stop=_RaisingEvent())  # must not raise

    assert "STOPPING=1" in stopped
