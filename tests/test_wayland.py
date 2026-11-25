"""Tests for Wayland discovery, protocol handlers, and the event loop."""

import socket

from unittest.mock import Mock, patch

import pytest

import cec_wake_daemon as cec
from pywayland.protocol.wayland import WlOutput as _WlOutput


# --------------------------------------------------------------------------
# Socket path + connectability
# --------------------------------------------------------------------------


def test_wayland_socket_path_with_runtime_dir(monkeypatch):
    """The path is derived from XDG_RUNTIME_DIR when it is set."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert cec._wayland_socket_path("wayland-0") == "/run/user/1000/wayland-0"


def test_wayland_socket_path_fallback(monkeypatch):
    """Without XDG_RUNTIME_DIR the display name is used literally."""
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert cec._wayland_socket_path("wayland-0") == "wayland-0"


class _FakeSock:
    """Stand-in for socket.socket with a controlled connect result."""

    blocking = False

    def __init__(self, exc=None):
        self.exc = exc

    def setblocking(self, blocking=False, *args, **kwargs):
        self.blocking = blocking

    def connect(self, _path):
        if self.exc is not None:
            raise self.exc

    def close(self):
        pass


def test_wayland_socket_connectable_returns_true(monkeypatch):
    """A connectable socket is reported as connectable."""
    monkeypatch.setattr(cec.socket, "socket", lambda *a, **k: _FakeSock())
    assert cec._wayland_socket_connectable("wayland-0") is True


def test_wayland_socket_connectable_blocking_is_connectable(monkeypatch):
    """A non-blocking connect that would block still means a live socket."""
    monkeypatch.setattr(
        cec.socket, "socket", lambda *a, **k: _FakeSock(BlockingIOError())
    )
    assert cec._wayland_socket_connectable("wayland-0") is True


def test_wayland_socket_connectable_failure(monkeypatch):
    """A refused/failed connect reports the socket as not connectable."""
    monkeypatch.setattr(
        cec.socket, "socket", lambda *a, **k: _FakeSock(OSError("nope"))
    )
    assert cec._wayland_socket_connectable("wayland-0") is False


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def test_scan_wayland_displays_orders_and_filters(monkeypatch):
    """Only wayland-<digits> survive, ordered by numeric index."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setattr(
        cec.os, "listdir", lambda p: ["wayland-2", "wayland-10", "wayland-1", "x"]
    )
    assert cec._scan_wayland_displays() == ["wayland-1", "wayland-2", "wayland-10"]


def test_scan_wayland_displays_empty_when_unavailable(monkeypatch):
    """No runtime dir yields an empty list."""
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert cec._scan_wayland_displays() == []


def test_scan_wayland_displays_survives_listdir_error(monkeypatch):
    """An error listing the runtime dir degrades to no displays."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setattr(cec.os, "listdir", lambda p: (_ for _ in ()).throw(OSError()))
    assert cec._scan_wayland_displays() == []


def test_scan_wayland_displays_skips_non_numeric_suffix(monkeypatch):
    """A wayland-<non-digit> entry is filtered out (not ordered)."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setattr(
        cec.os,
        "listdir",
        lambda p: ["wayland-1", "wayland-abc", "wayland-canvas"],
    )
    assert cec._scan_wayland_displays() == ["wayland-1"]


def test_pick_wayland_display_prefers_connectable_override(monkeypatch):
    """A WAYLAND_DISPLAY override wins when its socket connects."""
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-3")
    monkeypatch.setattr(cec, "_wayland_socket_connectable", lambda name: True)
    assert cec._pick_wayland_display() == "wayland-3"


def test_pick_wayland_display_skips_stale_override(monkeypatch):
    """A stale override is skipped in favor of a discovered display."""
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-9")
    monkeypatch.setattr(
        cec, "_wayland_socket_connectable", lambda name: name != "wayland-9"
    )
    monkeypatch.setattr(cec, "_scan_wayland_displays", lambda: ["wayland-0"])
    assert cec._pick_wayland_display() == "wayland-0"


def test_pick_wayland_display_returns_none(monkeypatch):
    """None is returned when nothing is connectable."""
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(cec, "_wayland_socket_connectable", lambda name: False)
    monkeypatch.setattr(cec, "_scan_wayland_displays", lambda: [])
    assert cec._pick_wayland_display() is None


def test_pick_wayland_display_falls_through_to_live_scan(monkeypatch):
    """A stale scanned display is skipped for a later connectable one."""
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        cec,
        "_wayland_socket_connectable",
        lambda name: name != "wayland-0",
    )
    monkeypatch.setattr(cec, "_scan_wayland_displays", lambda: ["wayland-0", "wayland-1"])
    assert cec._pick_wayland_display() == "wayland-1"


# --------------------------------------------------------------------------
# ext-idle-notify-v1 handler
# --------------------------------------------------------------------------


def test_setup_idle_notify_registers_handlers(monkeypatch):
    """Handlers are registered and dispatch on resume."""
    notification = Mock()
    notification.dispatcher = {}
    notifier = Mock(get_idle_notification=Mock(return_value=notification))
    globals_ = {"idle_notifier": notifier, "seat": Mock()}

    dispatch = Mock()
    assert cec._setup_idle_notify(globals_, 60000, dispatch) is True

    notification.dispatcher["idled"](notification)
    notification.dispatcher["resumed"](notification)
    dispatch.assert_called_once_with("ext-idle-notify-v1:resumed")


def test_setup_idle_notify_disabled_without_notifier(monkeypatch):
    """Returns False, leaving the source disabled, when objects are absent."""
    assert cec._setup_idle_notify({}, 60000, Mock()) is False


# --------------------------------------------------------------------------
# zwlr-output-power-management-v1 handler
# --------------------------------------------------------------------------


def test_setup_output_power_disabled_without_wlr(monkeypatch):
    """Returns False when pywayland lacks the protocol."""
    monkeypatch.setattr(cec, "HAVE_WLR_OUTPUT_POWER", False)
    assert cec._setup_output_power(Mock(), Mock()) is False


def test_setup_output_power_requires_manager(monkeypatch):
    """Returns False when the compositor has no manager object."""
    assert cec._setup_output_power({"outputs": []}, Mock()) is False


def test_setup_output_power_binds_and_dispatches_on_resume(monkeypatch):
    """Each output is bound and a dark->bright transition wakes the display."""
    dispatch = Mock()
    power1 = Mock()
    power1.dispatcher = {}
    power2 = Mock()
    power2.dispatcher = {}
    manager = Mock(get_output_power=Mock(side_effect=[power1, power2]))
    globals_ = {"output_power_manager": manager, "outputs": [Mock(), Mock()]}

    assert cec._setup_output_power(globals_, dispatch) is True

    # Bound twice (one per output); the last bind wins on the shared mock.
    power1.dispatcher["mode"](None, cec.WLR_OUTPUT_POWER_MODE_OFF)
    power1.dispatcher["mode"](None, cec.WLR_OUTPUT_POWER_MODE_ON)

    dispatch.assert_called_once_with(
        "zwlr-output-power-management-v1:mode-on"
    )


def test_setup_output_power_failed_handler(monkeypatch):
    """The failed handler logs without dispatching a wake event."""
    dispatch = Mock()
    power = Mock()
    power.dispatcher = {}
    manager = Mock(get_output_power=Mock(return_value=power))
    globals_ = {"output_power_manager": manager, "outputs": [Mock()]}

    cec._setup_output_power(globals_, dispatch)
    power.dispatcher["failed"](power)
    dispatch.assert_not_called()


def test_setup_output_power_no_dispatch_when_still_off(monkeypatch):
    """A mode transition that stays off does not wake the display."""
    dispatch = Mock()
    power = Mock()
    power.dispatcher = {}
    manager = Mock(get_output_power=Mock(return_value=power))
    globals_ = {"output_power_manager": manager, "outputs": [Mock()]}

    cec._setup_output_power(globals_, dispatch)
    power.dispatcher["mode"](None, cec.WLR_OUTPUT_POWER_MODE_OFF)
    power.dispatcher["mode"](None, cec.WLR_OUTPUT_POWER_MODE_OFF)

    dispatch.assert_not_called()


def test_run_wayland_loop_reconnects_after_disconnect(monkeypatch):
    """The outer loop retries when the display disappears or reconnects."""

    class _StopLoop(Exception):
        pass

    picks = []
    sleeps = []

    def _pick():
        picks.append(1)
        return "wayland-0" if len(picks) == 1 else None

    def _sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 3:
            raise _StopLoop

    monkeypatch.setattr(cec, "_pick_wayland_display", _pick)
    monkeypatch.setattr(cec, "_run_wayland_connection", Mock())
    monkeypatch.setattr(cec.time, "sleep", _sleep)

    with pytest.raises(_StopLoop):
        cec.run_wayland_loop(Mock(), 60000)

    # First iteration connected and reported the disconnect; the remaining
    # iterations saw no display and scheduled a reconnect.
    assert len(picks) >= 2
    assert all(s == cec.WAYLAND_RECONNECT_DELAY_SEC for s in sleeps)


# --------------------------------------------------------------------------
# Connection lifetime + event loop
# --------------------------------------------------------------------------


def test_run_wayland_connection_connect_failure_returns(monkeypatch):
    """A failed connect logs the error and never disconnects."""
    display = Mock()
    display.connect.side_effect = Exception("refused")
    with patch.object(cec, "WaylandDisplay", return_value=display):
        cec._run_wayland_connection(Mock(), 60000, "wayland-0")
    display.disconnect.assert_not_called()


def test_run_wayland_connection_disconnects_after_run(monkeypatch):
    """After the bind/run phase the connection is torn down."""
    display = Mock()
    with (
        patch.object(cec, "WaylandDisplay", return_value=display),
        patch.object(cec, "_bind_and_run") as bind,
    ):
        cec._run_wayland_connection(Mock(), 60000, "wayland-0")
    bind.assert_called_once()
    display.disconnect.assert_called_once()


def test_run_wayland_connection_bind_error_is_torn_down(monkeypatch):
    """A bind/run error still disconnects so the outer loop can retry."""
    display = Mock()
    with (
        patch.object(cec, "WaylandDisplay", return_value=display),
        patch.object(cec, "_bind_and_run", side_effect=Exception("boom")),
    ):
        cec._run_wayland_connection(Mock(), 60000, "wayland-0")
    display.disconnect.assert_called_once()


def test_bind_and_run_returns_without_loop_when_no_sources(monkeypatch):
    """With no active sources the loop is entered and an error is logged."""
    display = Mock()
    display.get_registry.return_value = Mock(dispatcher={})
    with (
        patch.object(cec, "_setup_idle_notify", return_value=False),
        patch.object(cec, "_setup_output_power", return_value=False),
        patch.object(display, "dispatch", side_effect=AssertionError("loop")) as disp,
    ):
        cec._bind_and_run(display, Mock(), 60000)
    disp.assert_not_called()  # never entered the dispatch loop


def test_bind_and_run_dispatches_until_disconnect(monkeypatch):
    """With sources active the loop runs until the compositor disconnects."""
    display = Mock()
    display.get_registry.return_value = Mock(dispatcher={})
    with (
        patch.object(cec, "_setup_idle_notify", return_value=True),
        patch.object(cec, "_setup_output_power", return_value=True),
        patch.object(display, "dispatch", side_effect=[0, 0, -1]) as disp,
    ):
        cec._bind_and_run(display, Mock(), 60000)
    disp.assert_called()  # loop exited cleanly (return value -1 == disconnect)


def test_bind_and_run_loop_error_is_logged(monkeypatch):
    """A dispatcher exception during the loop is logged, not raised."""
    display = Mock()
    display.get_registry.return_value = Mock(dispatcher={})
    with (
        patch.object(cec, "_setup_idle_notify", return_value=True),
        patch.object(cec, "_setup_output_power", return_value=True),
        patch.object(
            display, "dispatch", side_effect=[0, ValueError("loop blowup")]
        ),
    ):
        cec._bind_and_run(display, Mock(), 60000)


def test_bind_and_run_registers_global_handlers(monkeypatch):
    """The registry global handler binds each advertised protocol."""
    registry = Mock(dispatcher={})
    registry.bind = Mock(return_value=Mock())
    display = Mock()
    display.get_registry.return_value = registry
    with (
        patch.object(cec, "_setup_idle_notify", return_value=True),
        patch.object(cec, "_setup_output_power", return_value=True),
        patch.object(display, "dispatch", return_value=-1),
    ):
        cec._bind_and_run(display, Mock(), 60000)

    global_handler = registry.dispatcher["global"]
    for interface, version in [
        ("ext_idle_notifier_v1", 1),
        ("wl_seat", 1),
        ("wl_output", 1),
        ("zwlr_output_power_manager_v1", 1),
    ]:
        global_handler(registry, 42, interface, version)

    # bind(name, <protocol class>, version) -- assert each class was bound.
    called_classes = {call.args[1] for call in registry.bind.call_args_list}
    assert cec.ExtIdleNotifierV1 in called_classes
    assert cec.WlSeat in called_classes
    assert _WlOutput in called_classes
