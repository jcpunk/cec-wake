"""In-memory stand-in for python3-pywayland, matching its real call signatures.

Real pywayland (see https://github.com/flacjacket/pywayland) exposes:

  * ``Display.connect()`` / ``disconnect()`` -- no arguments.
  * ``Display.get_registry()`` -- no arguments, returns a proxy.
  * ``Display.roundtrip(*, queue=None)`` and ``dispatch(*, block=False,
    queue=None)`` -- both keyword-only.
  * Every protocol object exposes a ``.dispatcher`` mapping (see
    ``pywayland.dispatcher.Dispatcher``) whose ``__setitem__``/``__getitem__``
    accept the event name as a string key.
  * ``WlRegistry.bind(name, interface, version)`` -- positional.

Matching these signatures exactly (not just "close enough") means a daemon
bug that passes the wrong argument shape raises here too, instead of only
surfacing against the real library in production.
"""

from __future__ import annotations

import types
from typing import Any


class Dispatcher(dict):
    """Faithful stand-in for pywayland.dispatcher.Dispatcher.

    Keys are event names (str); unlike a plain dict a lookup of a key that
    was never set returns None, mirroring the real dispatcher's behaviour of
    invoking no-op for unregistered opcodes.
    """

    def __getitem__(self, key: str) -> Any:
        return self.get(key)


class _Proxy:
    """Base for fake protocol objects; always exposes .dispatcher."""

    def __init__(self) -> None:
        self.dispatcher = Dispatcher()


class ExtIdleNotifierV1(_Proxy):
    """Stand-in for pywayland.protocol.ext_idle_notify_v1.ExtIdleNotifierV1."""

    def get_idle_notification(self, _timeout_msec: int, _seat: Any) -> _Proxy:
        return _Proxy()


class WlSeat(_Proxy):
    """Stand-in for pywayland.protocol.wayland.WlSeat."""


class WlOutput(_Proxy):
    """Stand-in for pywayland.protocol.wayland.WlOutput."""


class ZwlrOutputPowerManagerV1(_Proxy):
    """Stand-in for the zwlr-output-power-management-v1 manager."""

    def get_output_power(self, _output: Any) -> _Proxy:
        return _Proxy()


class WlRegistry(_Proxy):
    """Stand-in for pywayland.protocol.wayland.WlRegistry."""

    def bind(self, name: int, interface: type[Any], version: int) -> Any:
        return interface()


class Display:
    """Stand-in for pywayland.client.Display."""

    def connect(self) -> None:
        return None

    def disconnect(self) -> None:
        return None

    def get_registry(self) -> WlRegistry:
        return WlRegistry()

    def roundtrip(self, *, queue: Any = None) -> int:
        return 0

    def dispatch(self, *, block: bool = False, queue: Any = None) -> int:
        return -1


def install() -> None:
    """Register pywayland + its protocol submodules in sys.modules."""
    import sys

    if "pywayland" in sys.modules:
        return

    pywayland = types.ModuleType("pywayland")
    client = types.ModuleType("pywayland.client")
    client.Display = Display

    ext_idle = types.ModuleType("pywayland.protocol.ext_idle_notify_v1")
    ext_idle.ExtIdleNotifierV1 = ExtIdleNotifierV1

    wl_wayland = types.ModuleType("pywayland.protocol.wayland")
    wl_wayland.WlSeat = WlSeat
    wl_wayland.WlOutput = WlOutput
    wl_wayland.WlRegistry = WlRegistry

    wlr = types.ModuleType("pywayland.protocol.wlr_output_power_management_unstable_v1")
    wlr.ZwlrOutputPowerManagerV1 = ZwlrOutputPowerManagerV1

    protocol = types.ModuleType("pywayland.protocol")
    protocol.ext_idle_notify_v1 = ext_idle
    protocol.wayland = wl_wayland
    protocol.wlr_output_power_management_unstable_v1 = wlr

    pywayland.client = client
    pywayland.protocol = protocol

    sys.modules["pywayland"] = pywayland
    sys.modules["pywayland.client"] = client
    sys.modules["pywayland.protocol"] = protocol
    sys.modules["pywayland.protocol.ext_idle_notify_v1"] = ext_idle
    sys.modules["pywayland.protocol.wayland"] = wl_wayland
    sys.modules["pywayland.protocol.wlr_output_power_management_unstable_v1"] = wlr
