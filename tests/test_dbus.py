"""Tests for the DBus wake sources (screensaver + logind)."""

import threading

import pytest
from unittest.mock import Mock, patch

import cec_wake_daemon as cec


# --------------------------------------------------------------------------
# logind session path encoding
# --------------------------------------------------------------------------


def test_logind_session_path_numeric():
    """A numeric session id maps to a plain session object path."""
    cec.os.environ["XDG_SESSION_ID"] = "2"
    assert cec._logind_session_path() == "/org/freedesktop/login1/session/2"


def test_logind_session_path_special_chars():
    """Non-alphanumeric characters are percent-encoded with a leading underscore."""
    cec.os.environ["XDG_SESSION_ID"] = "1a-2"
    # '-' (0x2d) is encoded as "_2d"; the rest pass through untouched.
    assert cec._logind_session_path() == "/org/freedesktop/login1/session/1a_2d2"


def test_logind_session_path_requires_session_id(monkeypatch):
    """A missing XDG_SESSION_ID is a hard error for callers."""
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    try:
        cec._logind_session_path()
        raise AssertionError("expected RuntimeError without XDG_SESSION_ID")
    except RuntimeError as exc:
        assert "XDG_SESSION_ID" in str(exc)


# --------------------------------------------------------------------------
# Screensaver subscriptions
# --------------------------------------------------------------------------


def test_subscribe_screensaver_dispatches_unlock(monkeypatch):
    """An unlock (is_active False) dispatches an ActiveChanged wake event."""
    bus = Mock()
    dispatch = Mock()
    cec._subscribe_screensaver(bus, dispatch)

    # First receiver is the ActiveChanged handler for the first interface.
    handler = bus.add_signal_receiver.call_args_list[0].args[0]
    handler(True)
    handler(False)
    expected = f"{cec.SCREENSAVER_INTERFACES[0]}:ActiveChanged"
    dispatch.assert_called_once_with(expected)


def test_subscribe_screensaver_ignores_lock(monkeypatch):
    """A lock (is_active True) does not dispatch a wake event."""
    bus = Mock()
    dispatch = Mock()
    cec._subscribe_screensaver(bus, dispatch)

    handler = bus.add_signal_receiver.call_args_list[1].args[0]
    handler(True)
    dispatch.assert_not_called()


def test_subscribe_screensaver_idle_dispatches_unlock(monkeypatch):
    """A SessionIdleChanged (is_idle False) dispatches a wake event."""
    bus = Mock()
    dispatch = Mock()
    cec._subscribe_screensaver(bus, dispatch)

    # Per interface the first receiver is ActiveChanged, the second is
    # SessionIdleChanged.  For the first interface that is index 1.
    handler = bus.add_signal_receiver.call_args_list[1].args[0]
    handler(True)
    handler(False)
    expected = f"{cec.SCREENSAVER_INTERFACES[0]}:SessionIdleChanged"
    dispatch.assert_called_once_with(expected)


# --------------------------------------------------------------------------
# logind IdleHint subscription
# --------------------------------------------------------------------------


def test_subscribe_logind_idle_dispatches_resume(monkeypatch):
    """A Transition of IdleHint True -> False dispatches a wake event."""
    cec.os.environ["XDG_SESSION_ID"] = "1"
    system_bus = Mock()
    system_bus.get_object.return_value = Mock(idle_hint=True)
    dispatch = Mock()

    cec._subscribe_logind_idle(system_bus, dispatch)

    handler = system_bus.add_signal_receiver.call_args_list[-1].args[0]
    handler(
        cec.LOGIND_SESSION_IFACE, {"IdleHint": False}, {}
    )
    dispatch.assert_called_once_with("logind:IdleHint")


def test_subscribe_logind_idle_skips_without_session(monkeypatch):
    """No XDG_SESSION_ID means no subscription is attempted."""
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    system_bus = Mock()
    cec._subscribe_logind_idle(system_bus, Mock())
    system_bus.add_signal_receiver.assert_not_called()


def test_subscribe_logind_idle_initial_read_fails(monkeypatch):
    """A failure reading the initial IdleHint is logged, not fatal."""
    cec.os.environ["XDG_SESSION_ID"] = "1"
    system_bus = Mock()
    system_bus.get_object.side_effect = cec.dbus.DBusException("nope")
    cec._subscribe_logind_idle(system_bus, Mock())
    # Subscription still proceeds so the daemon tracks future transitions.
    system_bus.add_signal_receiver.assert_called_once()


def test_subscribe_logind_idle_ignores_other_ifaces_and_keys(monkeypatch):
    """The PropertiesChanged handler ignores unrelated iface/keys."""
    cec.os.environ["XDG_SESSION_ID"] = "1"
    system_bus = Mock()
    system_bus.get_object.return_value = Mock(idle_hint=False)
    dispatch = Mock()

    cec._subscribe_logind_idle(system_bus, dispatch)
    handler = system_bus.add_signal_receiver.call_args_list[-1].args[0]

    handler("some.other.iface", {"IdleHint": False}, {})  # wrong iface -> return
    handler(
        cec.LOGIND_SESSION_IFACE, {"SomeOtherKey": True}, {}
    )  # key absent -> return
    dispatch.assert_not_called()


def test_subscribe_logind_idle_no_dispatch_when_already_idle(monkeypatch):
    """A repeated False IdleHint with no prior True does not dispatch."""
    cec.os.environ["XDG_SESSION_ID"] = "1"
    system_bus = Mock()
    system_bus.get_object.return_value = Mock(idle_hint=False)
    dispatch = Mock()

    cec._subscribe_logind_idle(system_bus, dispatch)
    handler = system_bus.add_signal_receiver.call_args_list[-1].args[0]
    handler(cec.LOGIND_SESSION_IFACE, {"IdleHint": False}, {})
    dispatch.assert_not_called()


# --------------------------------------------------------------------------
# logind PrepareForSleep subscription
# --------------------------------------------------------------------------


def test_subscribe_prepare_for_sleep_resume(monkeypatch):
    """PrepareForSleep(False) eventually dispatches a wake after the delay."""
    finished = threading.Event()

    def dispatch(_source):
        finished.set()

    monkeypatch.setattr(cec.time, "sleep", lambda *a, **k: None)

    bus = Mock()
    cec._subscribe_prepare_for_sleep(bus, dispatch)

    handler = bus.add_signal_receiver.call_args_list[-1].args[0]
    handler(True)  # suspending: no wake
    assert not finished.is_set()
    handler(False)  # resuming: wake after the delay
    assert finished.wait(2), "delayed dispatch never fired"


# --------------------------------------------------------------------------
# Main loop wiring
# --------------------------------------------------------------------------


def test_run_dbus_loop_returns_without_dbus(monkeypatch):
    """The loop is a no-op when python3-dbus is unavailable."""
    monkeypatch.setattr(cec, "HAVE_DBUS", False)
    with patch.object(cec, "GLib") as glib:
        cec.run_dbus_loop(Mock())
    glib.MainLoop.assert_not_called()


def test_run_dbus_loop_wires_sources(monkeypatch):
    """The loop subscribes to both buses and starts the GLib main loop."""
    monkeypatch.setattr(cec, "HAVE_DBUS", True)
    monkeypatch.setattr(cec.time, "sleep", lambda *a, **k: None)

    session_bus = Mock()
    system_bus = Mock()
    with (
        patch.object(cec.dbus.mainloop.glib, "DBusGMainLoop") as gmain,
        patch.object(cec.dbus, "SessionBus", return_value=session_bus),
        patch.object(cec.dbus, "SystemBus", return_value=system_bus),
        patch.object(cec, "GLib", Mock()) as glib,
    ):
        cec.run_dbus_loop(Mock())

    gmain.assert_called_once_with(set_as_default=True)
    session_bus.add_signal_receiver.assert_called()
    system_bus.add_signal_receiver.assert_called()
    glib.MainLoop.return_value.run.assert_called_once()


def test_run_dbus_loop_session_bus_error_is_handled(monkeypatch):
    """A session-bus subscription failure is logged; the loop still starts."""
    monkeypatch.setattr(cec, "HAVE_DBUS", True)
    monkeypatch.setattr(cec.time, "sleep", lambda *a, **k: None)

    session_bus = Mock()
    session_bus.add_signal_receiver.side_effect = cec.dbus.DBusException("refused")
    system_bus = Mock()
    with (
        patch.object(cec.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(cec.dbus, "SessionBus", return_value=session_bus),
        patch.object(cec.dbus, "SystemBus", return_value=system_bus),
        patch.object(cec, "GLib", Mock()) as glib,
    ):
        cec.run_dbus_loop(Mock())

    session_bus.add_signal_receiver.assert_called()
    glib.MainLoop.return_value.run.assert_called_once()


def test_run_dbus_loop_system_bus_error_is_handled(monkeypatch):
    """A system-bus subscription failure is logged; the loop still starts."""
    monkeypatch.setattr(cec, "HAVE_DBUS", True)
    monkeypatch.setattr(cec.time, "sleep", lambda *a, **k: None)

    session_bus = Mock()
    system_bus = Mock()
    system_bus.add_signal_receiver.side_effect = cec.dbus.DBusException("refused")
    with (
        patch.object(cec.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(cec.dbus, "SessionBus", return_value=session_bus),
        patch.object(cec.dbus, "SystemBus", return_value=system_bus),
        patch.object(cec, "GLib", Mock()) as glib,
    ):
        cec.run_dbus_loop(Mock())

    system_bus.add_signal_receiver.assert_called()
    glib.MainLoop.return_value.run.assert_called_once()


def test_run_dbus_loop_no_sources_returns(monkeypatch):
    """When no bus is reachable the loop is not started."""
    monkeypatch.setattr(cec, "HAVE_DBUS", True)

    session_bus = Mock()
    session_bus.add_signal_receiver.side_effect = cec.dbus.DBusException("refused")
    system_bus = Mock()
    system_bus.add_signal_receiver.side_effect = cec.dbus.DBusException("refused")
    with (
        patch.object(cec.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(cec.dbus, "SessionBus", return_value=session_bus),
        patch.object(cec.dbus, "SystemBus", return_value=system_bus),
        patch.object(cec, "GLib") as glib,
    ):
        cec.run_dbus_loop(Mock())

    glib.MainLoop.assert_not_called()


def test_run_dbus_loop_loop_error_is_handled(monkeypatch):
    """An error while the GLib main loop runs is logged, not raised."""
    monkeypatch.setattr(cec, "HAVE_DBUS", True)
    monkeypatch.setattr(cec.time, "sleep", lambda *a, **k: None)

    session_bus = Mock()
    system_bus = Mock()
    with (
        patch.object(cec.dbus.mainloop.glib, "DBusGMainLoop"),
        patch.object(cec.dbus, "SessionBus", return_value=session_bus),
        patch.object(cec.dbus, "SystemBus", return_value=system_bus),
        patch.object(cec, "GLib") as glib,
    ):
        glib.MainLoop.return_value.run.side_effect = Exception("loop died")
        cec.run_dbus_loop(Mock())

    glib.MainLoop.return_value.run.assert_called_once()
