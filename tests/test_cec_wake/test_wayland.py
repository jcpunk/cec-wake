"""Tests for Wayland discovery, protocol handlers, and the event loop."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from pywayland.protocol.wayland import WlOutput as _WlOutput

from cec_wake import wayland

# --------------------------------------------------------------------------
# Socket path + connectability
# --------------------------------------------------------------------------


def test_wayland_socket_path_with_runtime_dir(monkeypatch):
    """The path is derived from XDG_RUNTIME_DIR when it is set."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert wayland._wayland_socket_path("wayland-0") == "/run/user/1000/wayland-0"


def test_wayland_socket_path_fallback(monkeypatch):
    """Without XDG_RUNTIME_DIR the display name is used literally."""
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert wayland._wayland_socket_path("wayland-0") == "wayland-0"


def test_wayland_socket_connectable_real_socket_api():
    """
    _wayland_socket_connectable() against a real AF_UNIX socket.

    Regression test: a prior implementation called
    ``sock.setblocking(blocking=False)``, which raises TypeError against the
    real stdlib socket (setblocking takes only a positional argument). The
    unit-only mock previously used here accepted the keyword and masked the
    bug; this test exercises the real socket module instead.
    """
    assert wayland._wayland_socket_connectable("/nonexistent/path/for/test") is False


class _FakeSock:
    """Stand-in for socket.socket with a controlled connect result.

    setblocking() accepts only a positional argument, matching the real
    stdlib socket (``socket.setblocking(flag, /)``); a call using the
    keyword form raises TypeError here exactly as it would for real.
    """

    def __init__(self, exc=None):
        self.exc = exc
        self.blocking = True

    def setblocking(self, flag, /):
        self.blocking = flag

    def connect(self, _path):
        if self.exc is not None:
            raise self.exc

    def close(self):
        pass


def test_wayland_socket_connectable_returns_true(monkeypatch):
    """A connectable socket is reported as connectable."""
    monkeypatch.setattr(wayland.socket, "socket", lambda *a, **k: _FakeSock())
    assert wayland._wayland_socket_connectable("wayland-0") is True


def test_wayland_socket_connectable_blocking_is_connectable(monkeypatch):
    """A non-blocking connect that would block still means a live socket."""
    monkeypatch.setattr(
        wayland.socket, "socket", lambda *a, **k: _FakeSock(BlockingIOError())
    )
    assert wayland._wayland_socket_connectable("wayland-0") is True


def test_wayland_socket_connectable_failure(monkeypatch):
    """A refused/failed connect reports the socket as not connectable."""
    monkeypatch.setattr(
        wayland.socket, "socket", lambda *a, **k: _FakeSock(OSError("nope"))
    )
    assert wayland._wayland_socket_connectable("wayland-0") is False


def test_wayland_socket_connectable_closes_on_setblocking_error(monkeypatch):
    """A socket is still closed if setblocking() itself raises."""
    closed = []

    class _BrokenSock:
        def setblocking(self, flag, /):
            raise OSError("broken")

        def close(self):
            closed.append(1)

    monkeypatch.setattr(wayland.socket, "socket", lambda *a, **k: _BrokenSock())
    with pytest.raises(OSError, match="broken"):
        wayland._wayland_socket_connectable("wayland-0")
    assert closed == [1]


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def test_scan_wayland_displays_orders_and_filters(tmp_path, monkeypatch):
    """Only wayland-<digits> survive, ordered by numeric index."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    for name in ("wayland-2", "wayland-10", "wayland-1", "x"):
        (tmp_path / name).touch()
    assert wayland._scan_wayland_displays() == ["wayland-1", "wayland-2", "wayland-10"]


def test_scan_wayland_displays_empty_when_unavailable(monkeypatch):
    """No runtime dir yields an empty list."""
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert wayland._scan_wayland_displays() == []


def test_scan_wayland_displays_survives_missing_dir(monkeypatch):
    """A runtime dir that does not exist degrades to no displays."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/nonexistent/runtime/dir")
    assert wayland._scan_wayland_displays() == []


def test_scan_wayland_displays_skips_non_numeric_suffix(tmp_path, monkeypatch):
    """A wayland-<non-digit> entry is filtered out (not ordered)."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    for name in ("wayland-1", "wayland-abc", "wayland-canvas"):
        (tmp_path / name).touch()
    assert wayland._scan_wayland_displays() == ["wayland-1"]


def test_pick_wayland_display_prefers_connectable_override(monkeypatch):
    """A WAYLAND_DISPLAY override wins when its socket connects."""
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-3")
    monkeypatch.setattr(wayland, "_wayland_socket_connectable", lambda _name: True)
    assert wayland._pick_wayland_display() == "wayland-3"


def test_pick_wayland_display_skips_stale_override(monkeypatch):
    """A stale override is skipped in favor of a discovered display."""
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-9")
    monkeypatch.setattr(
        wayland, "_wayland_socket_connectable", lambda name: name != "wayland-9"
    )
    monkeypatch.setattr(wayland, "_scan_wayland_displays", lambda: ["wayland-0"])
    assert wayland._pick_wayland_display() == "wayland-0"


def test_pick_wayland_display_returns_none(monkeypatch):
    """None is returned when nothing is connectable."""
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(wayland, "_wayland_socket_connectable", lambda _name: False)
    monkeypatch.setattr(wayland, "_scan_wayland_displays", list)
    assert wayland._pick_wayland_display() is None


def test_pick_wayland_display_falls_through_to_live_scan(monkeypatch):
    """A stale scanned display is skipped for a later connectable one."""
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        wayland, "_wayland_socket_connectable", lambda name: name != "wayland-0"
    )
    monkeypatch.setattr(
        wayland, "_scan_wayland_displays", lambda: ["wayland-0", "wayland-1"]
    )
    assert wayland._pick_wayland_display() == "wayland-1"


# --------------------------------------------------------------------------
# ext-idle-notify-v1 handler
# --------------------------------------------------------------------------


def test_setup_idle_notify_registers_handlers():
    """Handlers are registered and dispatch on resume."""
    notification = Mock()
    notification.dispatcher = {}
    notifier = Mock(get_idle_notification=Mock(return_value=notification))
    globals_ = {"idle_notifier": notifier, "seat": Mock()}

    dispatch = Mock()
    assert wayland._setup_idle_notify(globals_, 60000, dispatch) is True

    notification.dispatcher["idled"](notification)
    notification.dispatcher["resumed"](notification)
    dispatch.assert_called_once_with("ext-idle-notify-v1:resumed")


def test_setup_idle_notify_disabled_without_notifier():
    """Returns False, leaving the source disabled, when objects are absent."""
    assert wayland._setup_idle_notify({}, 60000, Mock()) is False


# --------------------------------------------------------------------------
# zwlr-output-power-management-v1 handler
# --------------------------------------------------------------------------


def test_setup_output_power_disabled_without_wlr(monkeypatch):
    """Returns False when pywayland lacks the protocol."""
    monkeypatch.setattr(wayland, "HAVE_WLR_OUTPUT_POWER", False)
    assert wayland._setup_output_power(Mock(), Mock()) is False


def test_setup_output_power_requires_manager():
    """Returns False when the compositor has no manager object."""
    assert wayland._setup_output_power({"outputs": []}, Mock()) is False


def test_setup_output_power_binds_and_dispatches_on_resume():
    """Each output is bound and a dark->bright transition wakes the display."""
    dispatch = Mock()
    power1 = Mock()
    power1.dispatcher = {}
    power2 = Mock()
    power2.dispatcher = {}
    manager = Mock(get_output_power=Mock(side_effect=[power1, power2]))
    globals_ = {"output_power_manager": manager, "outputs": [Mock(), Mock()]}

    assert wayland._setup_output_power(globals_, dispatch) is True

    power1.dispatcher["mode"](None, wayland.WLR_OUTPUT_POWER_MODE_OFF)
    power1.dispatcher["mode"](None, wayland.WLR_OUTPUT_POWER_MODE_ON)

    dispatch.assert_called_once_with("zwlr-output-power-management-v1:mode-on")


def test_setup_output_power_failed_handler():
    """The failed handler logs without dispatching a wake event."""
    dispatch = Mock()
    power = Mock()
    power.dispatcher = {}
    manager = Mock(get_output_power=Mock(return_value=power))
    globals_ = {"output_power_manager": manager, "outputs": [Mock()]}

    wayland._setup_output_power(globals_, dispatch)
    power.dispatcher["failed"](power)
    dispatch.assert_not_called()


def test_setup_output_power_no_dispatch_when_still_off():
    """A mode transition that stays off does not wake the display."""
    dispatch = Mock()
    power = Mock()
    power.dispatcher = {}
    manager = Mock(get_output_power=Mock(return_value=power))
    globals_ = {"output_power_manager": manager, "outputs": [Mock()]}

    wayland._setup_output_power(globals_, dispatch)
    power.dispatcher["mode"](None, wayland.WLR_OUTPUT_POWER_MODE_OFF)
    power.dispatcher["mode"](None, wayland.WLR_OUTPUT_POWER_MODE_OFF)

    dispatch.assert_not_called()


def test_run_wayland_loop_reconnects_after_disconnect(monkeypatch):
    """The outer loop retries when the display disappears or reconnects."""

    class _StopLoop(Exception):
        """Sentinel raised to break out of the otherwise-infinite loop."""

    picks = []
    sleeps = []

    def _pick():
        picks.append(1)
        return "wayland-0" if len(picks) == 1 else None

    def _sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 3:
            raise _StopLoop

    monkeypatch.setattr(wayland, "HAVE_WAYLAND", True)
    monkeypatch.setattr(wayland, "_pick_wayland_display", _pick)
    monkeypatch.setattr(wayland, "_run_wayland_connection", Mock())
    monkeypatch.setattr(wayland.time, "sleep", _sleep)

    with pytest.raises(_StopLoop):
        wayland.run_wayland_loop(Mock(), 60000)

    # First iteration connected and reported the disconnect; the remaining
    # iterations saw no display and scheduled a reconnect.
    assert len(picks) >= 2
    assert all(s == wayland.WAYLAND_RECONNECT_DELAY_SEC for s in sleeps)


def test_run_wayland_loop_noop_without_pywayland(monkeypatch):
    """The loop returns immediately when python3-pywayland is unavailable."""
    monkeypatch.setattr(wayland, "HAVE_WAYLAND", False)
    pick = Mock()
    monkeypatch.setattr(wayland, "_pick_wayland_display", pick)
    wayland.run_wayland_loop(Mock(), 60000)
    pick.assert_not_called()


# --------------------------------------------------------------------------
# Connection lifetime + event loop
# --------------------------------------------------------------------------


def test_run_wayland_connection_connect_failure_returns():
    """A failed connect logs the error and never disconnects."""
    display = Mock()
    display.connect.side_effect = Exception("refused")
    with patch.object(wayland, "WaylandDisplay", return_value=display):
        wayland._run_wayland_connection(Mock(), 60000, "wayland-0")
    display.disconnect.assert_not_called()


def test_run_wayland_connection_disconnects_after_run():
    """After the bind/run phase the connection is torn down."""
    display = Mock()
    with (
        patch.object(wayland, "WaylandDisplay", return_value=display),
        patch.object(wayland, "_bind_and_run") as bind,
    ):
        wayland._run_wayland_connection(Mock(), 60000, "wayland-0")
    bind.assert_called_once()
    display.disconnect.assert_called_once()


def test_run_wayland_connection_bind_error_is_torn_down():
    """A bind/run error still disconnects so the outer loop can retry."""
    display = Mock()
    with (
        patch.object(wayland, "WaylandDisplay", return_value=display),
        patch.object(wayland, "_bind_and_run", side_effect=Exception("boom")),
    ):
        wayland._run_wayland_connection(Mock(), 60000, "wayland-0")
    display.disconnect.assert_called_once()


def test_bind_and_run_returns_without_loop_when_no_sources():
    """With no active sources the loop is never entered."""
    display = Mock()
    display.get_registry.return_value = Mock(dispatcher={})
    with (
        patch.object(wayland, "_setup_idle_notify", return_value=False),
        patch.object(wayland, "_setup_output_power", return_value=False),
        patch.object(display, "dispatch", side_effect=AssertionError("loop")) as disp,
    ):
        wayland._bind_and_run(display, Mock(), 60000)
    disp.assert_not_called()


def test_bind_and_run_dispatches_until_disconnect():
    """With sources active the loop runs until the compositor disconnects."""
    display = Mock()
    display.get_registry.return_value = Mock(dispatcher={})
    with (
        patch.object(wayland, "_setup_idle_notify", return_value=True),
        patch.object(wayland, "_setup_output_power", return_value=True),
        patch.object(display, "dispatch", side_effect=[0, 0, -1]) as disp,
    ):
        wayland._bind_and_run(display, Mock(), 60000)
    disp.assert_called()


def test_bind_and_run_loop_error_is_logged():
    """A dispatcher exception during the loop is logged, not raised."""
    display = Mock()
    display.get_registry.return_value = Mock(dispatcher={})
    with (
        patch.object(wayland, "_setup_idle_notify", return_value=True),
        patch.object(wayland, "_setup_output_power", return_value=True),
        patch.object(display, "dispatch", side_effect=[0, ValueError("loop blowup")]),
    ):
        wayland._bind_and_run(display, Mock(), 60000)


def test_bind_and_run_registers_global_handlers():
    """The registry global handler binds each advertised protocol."""
    registry = Mock(dispatcher={})
    registry.bind = Mock(return_value=Mock())
    display = Mock()
    display.get_registry.return_value = registry
    with (
        patch.object(wayland, "_setup_idle_notify", return_value=True),
        patch.object(wayland, "_setup_output_power", return_value=True),
        patch.object(display, "dispatch", return_value=-1),
    ):
        wayland._bind_and_run(display, Mock(), 60000)

    global_handler = registry.dispatcher["global"]
    for interface, version in [
        ("ext_idle_notifier_v1", 1),
        ("wl_seat", 1),
        ("wl_output", 1),
        ("zwlr_output_power_manager_v1", 1),
    ]:
        global_handler(registry, 42, interface, version)

    called_classes = {call.args[1] for call in registry.bind.call_args_list}
    assert wayland.ExtIdleNotifierV1 in called_classes
    assert wayland.WlSeat in called_classes
    assert _WlOutput in called_classes


def test_bind_and_run_skips_wlr_output_power_global_when_unavailable(monkeypatch):
    """The zwlr-output-power-management-v1 global is ignored without support."""
    monkeypatch.setattr(wayland, "HAVE_WLR_OUTPUT_POWER", False)
    registry = Mock(dispatcher={})
    registry.bind = Mock(return_value=Mock())
    display = Mock()
    display.get_registry.return_value = registry
    with (
        patch.object(wayland, "_setup_idle_notify", return_value=True),
        patch.object(wayland, "_setup_output_power", return_value=True),
        patch.object(display, "dispatch", return_value=-1),
    ):
        wayland._bind_and_run(display, Mock(), 60000)

    global_handler = registry.dispatcher["global"]
    global_handler(registry, 42, "zwlr_output_power_manager_v1", 1)
    registry.bind.assert_not_called()
