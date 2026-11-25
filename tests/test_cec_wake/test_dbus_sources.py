"""Tests for the DBus wake sources (screensaver + logind)."""

from __future__ import annotations

import threading
import types
from unittest.mock import Mock, patch

from cec_wake import dbus_sources

# --------------------------------------------------------------------------
# logind session path encoding
# --------------------------------------------------------------------------


def test_logind_session_path_numeric(monkeypatch):
    """A numeric session id maps to a plain session object path."""
    monkeypatch.setenv("XDG_SESSION_ID", "2")
    assert dbus_sources._logind_session_path() == "/org/freedesktop/login1/session/2"


def test_logind_session_path_special_chars(monkeypatch):
    """Non-alphanumeric characters are percent-encoded with a leading underscore."""
    monkeypatch.setenv("XDG_SESSION_ID", "1a-2")
    # '-' (0x2d) is encoded as "_2d"; the rest pass through untouched.
    assert (
        dbus_sources._logind_session_path() == "/org/freedesktop/login1/session/1a_2d2"
    )


def test_logind_session_path_requires_session_id(monkeypatch):
    """A missing XDG_SESSION_ID is a hard error for callers."""
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    try:
        dbus_sources._logind_session_path()
        raise AssertionError("expected RuntimeError without XDG_SESSION_ID")
    except RuntimeError as exc:
        assert "XDG_SESSION_ID" in str(exc)


# --------------------------------------------------------------------------
# Screensaver subscriptions
# --------------------------------------------------------------------------


def test_subscribe_screensaver_dispatches_unlock():
    """An unlock (is_active False) dispatches an ActiveChanged wake event."""
    bus = dbus_sources.dbus.SessionBus()
    dispatch = Mock()
    dbus_sources._subscribe_screensaver(bus, dispatch)

    # First receiver is the ActiveChanged handler for the first interface.
    handler = bus.receivers[0]
    handler(True)
    handler(False)
    expected = f"{dbus_sources.SCREENSAVER_INTERFACES[0]}:ActiveChanged"
    dispatch.assert_called_once_with(expected)


def test_subscribe_screensaver_ignores_lock():
    """A lock (is_active True) does not dispatch a wake event."""
    bus = dbus_sources.dbus.SessionBus()
    dispatch = Mock()
    dbus_sources._subscribe_screensaver(bus, dispatch)

    handler = bus.receivers[1]
    handler(True)
    dispatch.assert_not_called()


def test_subscribe_screensaver_idle_dispatches_unlock():
    """A SessionIdleChanged (is_idle False) dispatches a wake event."""
    bus = dbus_sources.dbus.SessionBus()
    dispatch = Mock()
    dbus_sources._subscribe_screensaver(bus, dispatch)

    # Per interface the first receiver is ActiveChanged, the second is
    # SessionIdleChanged.  For the first interface that is index 1.
    handler = bus.receivers[1]
    handler(True)
    handler(False)
    expected = f"{dbus_sources.SCREENSAVER_INTERFACES[0]}:SessionIdleChanged"
    dispatch.assert_called_once_with(expected)


# --------------------------------------------------------------------------
# logind IdleHint subscription
# --------------------------------------------------------------------------


def test_subscribe_logind_idle_dispatches_resume(monkeypatch):
    """A Transition of IdleHint True -> False dispatches a wake event."""
    monkeypatch.setenv("XDG_SESSION_ID", "1")
    system_bus = dbus_sources.dbus.SystemBus()
    system_bus.queue_object(types.SimpleNamespace(properties={"IdleHint": True}))
    dispatch = Mock()

    dbus_sources._subscribe_logind_idle(system_bus, dispatch)

    handler = system_bus.receivers[-1]
    handler(dbus_sources.LOGIND_SESSION_IFACE, {"IdleHint": False}, {})
    dispatch.assert_called_once_with("logind:IdleHint")


def test_subscribe_logind_idle_skips_without_session(monkeypatch):
    """No XDG_SESSION_ID means no subscription is attempted."""
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    system_bus = dbus_sources.dbus.SystemBus()
    dbus_sources._subscribe_logind_idle(system_bus, Mock())
    assert system_bus.receivers == []


def test_subscribe_logind_idle_initial_read_fails(monkeypatch):
    """A failure reading the initial IdleHint is logged, not fatal."""
    monkeypatch.setenv("XDG_SESSION_ID", "1")
    system_bus = dbus_sources.dbus.SystemBus()
    system_bus.queue_object_error(dbus_sources.dbus.DBusException("nope"))
    dbus_sources._subscribe_logind_idle(system_bus, Mock())
    # Subscription still proceeds so the daemon tracks future transitions.
    assert len(system_bus.receivers) == 1


def test_subscribe_logind_idle_ignores_other_ifaces_and_keys(monkeypatch):
    """The PropertiesChanged handler ignores unrelated iface/keys."""
    monkeypatch.setenv("XDG_SESSION_ID", "1")
    system_bus = dbus_sources.dbus.SystemBus()
    system_bus.queue_object(types.SimpleNamespace(properties={"IdleHint": False}))
    dispatch = Mock()

    dbus_sources._subscribe_logind_idle(system_bus, dispatch)
    handler = system_bus.receivers[-1]

    handler("some.other.iface", {"IdleHint": False}, {})  # wrong iface -> return
    handler(
        dbus_sources.LOGIND_SESSION_IFACE, {"SomeOtherKey": True}, {}
    )  # key absent -> return
    dispatch.assert_not_called()


def test_subscribe_logind_idle_no_dispatch_when_already_idle(monkeypatch):
    """A repeated False IdleHint with no prior True does not dispatch."""
    monkeypatch.setenv("XDG_SESSION_ID", "1")
    system_bus = dbus_sources.dbus.SystemBus()
    system_bus.queue_object(types.SimpleNamespace(properties={"IdleHint": False}))
    dispatch = Mock()

    dbus_sources._subscribe_logind_idle(system_bus, dispatch)
    handler = system_bus.receivers[-1]
    handler(dbus_sources.LOGIND_SESSION_IFACE, {"IdleHint": False}, {})
    dispatch.assert_not_called()


# --------------------------------------------------------------------------
# logind PrepareForSleep subscription
# --------------------------------------------------------------------------


def test_subscribe_prepare_for_sleep_resume(monkeypatch):
    """PrepareForSleep(False) eventually dispatches a wake after the delay."""
    finished = threading.Event()

    def dispatch(_source):
        finished.set()

    monkeypatch.setattr(dbus_sources.time, "sleep", lambda *a, **k: None)

    bus = dbus_sources.dbus.SystemBus()
    dbus_sources._subscribe_prepare_for_sleep(bus, dispatch)

    handler = bus.receivers[-1]
    handler(True)  # suspending: no wake
    assert not finished.is_set()
    handler(False)  # resuming: wake after the delay
    assert finished.wait(2), "delayed dispatch never fired"


# --------------------------------------------------------------------------
# Main loop wiring
# --------------------------------------------------------------------------


def test_run_dbus_loop_returns_without_dbus(monkeypatch):
    """The loop is a no-op when python3-dbus is unavailable."""
    monkeypatch.setattr(dbus_sources, "HAVE_DBUS", False)
    with patch.object(dbus_sources, "GLib") as glib:
        dbus_sources.run_dbus_loop(Mock())
    glib.MainLoop.assert_not_called()


def test_run_dbus_loop_wires_sources(monkeypatch):
    """The loop subscribes to both buses and starts the GLib main loop."""
    monkeypatch.setattr(dbus_sources, "HAVE_DBUS", True)
    monkeypatch.setattr(dbus_sources.time, "sleep", lambda *a, **k: None)

    session_bus = dbus_sources.dbus.SessionBus()
    system_bus = dbus_sources.dbus.SystemBus()
    with (
        patch.object(dbus_sources.dbus.mainloop.glib, "DBusGMainLoop") as gmain,
        patch.object(dbus_sources.dbus, "SessionBus", return_value=session_bus),
        patch.object(dbus_sources.dbus, "SystemBus", return_value=system_bus),
        patch.object(dbus_sources, "GLib", Mock()) as glib,
    ):
        dbus_sources.run_dbus_loop(Mock())

    gmain.assert_called_once_with(set_as_default=True)
    assert session_bus.receivers
    assert system_bus.receivers
    glib.MainLoop.return_value.run.assert_called_once()


def test_run_dbus_loop_session_bus_error_is_handled(monkeypatch):
    """A session-bus subscription failure is logged; the loop still starts."""
    monkeypatch.setattr(dbus_sources, "HAVE_DBUS", True)
    monkeypatch.setattr(dbus_sources.time, "sleep", lambda *a, **k: None)

    class _BrokenSessionBus:
        def add_signal_receiver(self, *_args, **_kwargs):
            raise dbus_sources.dbus.DBusException("refused")

    system_bus = dbus_sources.dbus.SystemBus()
    with (
        patch.object(dbus_sources.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(dbus_sources.dbus, "SessionBus", return_value=_BrokenSessionBus()),
        patch.object(dbus_sources.dbus, "SystemBus", return_value=system_bus),
        patch.object(dbus_sources, "GLib", Mock()) as glib,
    ):
        dbus_sources.run_dbus_loop(Mock())

    assert system_bus.receivers
    glib.MainLoop.return_value.run.assert_called_once()


def test_run_dbus_loop_system_bus_error_is_handled(monkeypatch):
    """A system-bus subscription failure is logged; the loop still starts."""
    monkeypatch.setattr(dbus_sources, "HAVE_DBUS", True)
    monkeypatch.setattr(dbus_sources.time, "sleep", lambda *a, **k: None)

    class _BrokenSystemBus:
        def get_object(self, *_args, **_kwargs):
            raise dbus_sources.dbus.DBusException("refused")

        def add_signal_receiver(self, *_args, **_kwargs):
            raise dbus_sources.dbus.DBusException("refused")

    session_bus = dbus_sources.dbus.SessionBus()
    with (
        patch.object(dbus_sources.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(dbus_sources.dbus, "SessionBus", return_value=session_bus),
        patch.object(dbus_sources.dbus, "SystemBus", return_value=_BrokenSystemBus()),
        patch.object(dbus_sources, "GLib", Mock()) as glib,
    ):
        dbus_sources.run_dbus_loop(Mock())

    assert session_bus.receivers
    glib.MainLoop.return_value.run.assert_called_once()


def test_run_dbus_loop_no_sources_returns(monkeypatch):
    """When no bus is reachable the loop is not started."""
    monkeypatch.setattr(dbus_sources, "HAVE_DBUS", True)

    class _BrokenBus:
        def get_object(self, *_args, **_kwargs):
            raise dbus_sources.dbus.DBusException("refused")

        def add_signal_receiver(self, *_args, **_kwargs):
            raise dbus_sources.dbus.DBusException("refused")

    with (
        patch.object(dbus_sources.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(dbus_sources.dbus, "SessionBus", return_value=_BrokenBus()),
        patch.object(dbus_sources.dbus, "SystemBus", return_value=_BrokenBus()),
        patch.object(dbus_sources, "GLib") as glib,
    ):
        dbus_sources.run_dbus_loop(Mock())

    glib.MainLoop.assert_not_called()


def test_run_dbus_loop_loop_error_is_handled(monkeypatch):
    """An error while the GLib main loop runs is logged, not raised."""
    monkeypatch.setattr(dbus_sources, "HAVE_DBUS", True)
    monkeypatch.setattr(dbus_sources.time, "sleep", lambda *a, **k: None)

    session_bus = dbus_sources.dbus.SessionBus()
    system_bus = dbus_sources.dbus.SystemBus()
    with (
        patch.object(dbus_sources.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(dbus_sources.dbus, "SessionBus", return_value=session_bus),
        patch.object(dbus_sources.dbus, "SystemBus", return_value=system_bus),
        patch.object(dbus_sources, "GLib") as glib,
    ):
        glib.MainLoop.return_value.run.side_effect = Exception("loop died")
        dbus_sources.run_dbus_loop(Mock())

    glib.MainLoop.return_value.run.assert_called_once()
