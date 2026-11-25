"""Tests for the CEC device readiness check."""

import cec_wake_daemon as cec


def test_wait_for_existing_writable(tmp_path):
    """An existing, writable path is accepted on the first poll."""
    adapter = tmp_path / "cec"
    adapter.touch()
    cec.wait_for_device(str(adapter), timeout=1)


def test_wait_for_missing_raises_on_timeout(monkeypatch):
    """A path that never appears raises after the timeout elapses."""
    # Skip the real sleep so the timeout path is fast.
    monkeypatch.setattr(cec.time, "sleep", lambda *_: None)
    try:
        cec.wait_for_device("/nonexistent/cec-device", timeout=1)
        raise AssertionError("expected RuntimeError on timeout")
    except RuntimeError as exc:
        assert "not found" in str(exc)


def test_wait_for_unwritable_raises(monkeypatch):
    """A present but non-writable node raises with a guidance message."""
    monkeypatch.setattr(cec.Path, "exists", lambda self: True)
    monkeypatch.setattr(cec.os, "access", lambda p, mode: False)
    try:
        cec.wait_for_device("/dev/cec", timeout=1)
        raise AssertionError("expected RuntimeError on denied access")
    except RuntimeError as exc:
        assert "No write access" in str(exc)
