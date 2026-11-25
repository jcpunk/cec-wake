"""Tests for the CEC device readiness check."""

from __future__ import annotations

import pytest

from cec_wake import device


def test_wait_for_existing_writable(tmp_path):
    """An existing, writable path is accepted on the first poll."""
    adapter = tmp_path / "cec"
    adapter.touch()
    device.wait_for_device(str(adapter), timeout=1)


def test_wait_for_missing_raises_on_timeout(monkeypatch):
    """A path that never appears raises after the timeout elapses."""
    # Skip the real sleep so the timeout path is fast.
    monkeypatch.setattr(device.time, "sleep", lambda *_: None)
    with pytest.raises(RuntimeError, match="not found"):
        device.wait_for_device("/nonexistent/cec-device", timeout=1)


def test_wait_for_unwritable_raises(monkeypatch):
    """A present but non-writable node raises with a guidance message."""
    monkeypatch.setattr(device.Path, "exists", lambda self: True)
    monkeypatch.setattr(device.os, "access", lambda p, mode: False)
    with pytest.raises(RuntimeError, match="No write access"):
        device.wait_for_device("/dev/cec", timeout=1)
