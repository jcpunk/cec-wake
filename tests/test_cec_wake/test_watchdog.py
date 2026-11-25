"""Tests for the systemd watchdog helper."""

from __future__ import annotations

import threading

from cec_wake import watchdog as watchdog_mod


def test_setup_watchdog_without_env_returns(monkeypatch):
    """Without WATCHDOG_USEC set the watchdog is a silent no-op."""
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    watchdog_mod.setup_watchdog()


def test_setup_watchdog_starts_ping_loop(monkeypatch):
    """With WATCHDOG_USEC set, a thread pings systemd at half the interval."""
    monkeypatch.setenv("WATCHDOG_USEC", "4000000")  # interval = 2s
    # Avoid the real 1s sleep keeping the ping thread alive.
    monkeypatch.setattr(watchdog_mod.time, "sleep", lambda *_a, **_k: None)

    pings = []

    def _send(message):
        pings.append(message)
        raise RuntimeError("stop the ping loop after one ping")

    monkeypatch.setattr(watchdog_mod, "sd_notify", _send)

    # The ping loop is an unbounded ``while True``; it only stops by raising.
    # Capture that exception so it is not reported as an unhandled thread error.
    collected = {}

    def _excepthook(args):
        collected["value"] = args.exc_value

    old_hook = threading.excepthook
    threading.excepthook = _excepthook
    try:
        watchdog_mod.setup_watchdog()
        for thread in threading.enumerate():
            if thread.name == "watchdog":
                thread.join(2)
    finally:
        threading.excepthook = old_hook

    assert pings == ["WATCHDOG=1"]
    assert isinstance(collected.get("value"), RuntimeError)
