"""In-memory stand-in for python3-dbus + python3-gobject.

Matches the real call signatures so a daemon bug that passes the wrong
argument shape raises here too, instead of only surfacing against the real
libraries in production:

  * ``dbus.bus.BusConnection.add_signal_receiver(handler_function,
    signal_name=None, dbus_interface=None, bus_name=None, path=None,
    **keywords)``
  * ``dbus.bus.BusConnection.get_object(bus_name, object_path,
    introspect=True, follow_name_owner_changes=False, **kwargs)``
  * ``dbus.proxies.Interface.__init__(self, object, dbus_interface)`` with
    DBus methods reached through attribute access (``__getattr__`` ->
    ``get_dbus_method``), not a literal ``.Get()`` implementation.
  * ``dbus.mainloop.glib.DBusGMainLoop(set_as_default=...)`` returns nothing
    useful to the caller; it is called for its side effect.
  * ``gi.repository.GLib.MainLoop()`` with a no-argument ``.run()``.
"""

from __future__ import annotations

import sys
import types
from typing import Any


class DBusException(Exception):
    """Stand-in for dbus.DBusException."""


class Bus:
    """Stand-in for a D-Bus connection (dbus.bus.BusConnection).

    ``add_signal_receiver`` records the handlers that were registered so
    tests can invoke them directly.  ``get_object`` returns whatever was
    queued with ``queue_object`` (or raises DBusException, matching a
    service that is not reachable), exercising both code paths exactly as
    the real bus would on success or on
    ``dbus.exceptions.DBusException: ServiceUnknown``.
    """

    def __init__(self) -> None:
        self.receivers: list[Any] = []
        self._queued_object: Any = None
        self._queued_object_error: Exception | None = None

    def add_signal_receiver(
        self,
        handler_function: Any,
        signal_name: str | None = None,
        dbus_interface: str | None = None,
        bus_name: str | None = None,
        path: str | None = None,
        **_keywords: Any,
    ) -> None:
        self.receivers.append(handler_function)

    def queue_object(self, obj: Any) -> None:
        """Arrange for the next get_object() call to return obj."""
        self._queued_object = obj

    def queue_object_error(self, exc: Exception) -> None:
        """Arrange for the next get_object() call to raise exc."""
        self._queued_object_error = exc

    def get_object(
        self,
        bus_name: str,
        object_path: str,
        introspect: bool = True,  # noqa: FBT001, FBT002 - matches real signature.
        follow_name_owner_changes: bool = False,  # noqa: FBT001, FBT002
        **_kwargs: Any,
    ) -> Any:
        if self._queued_object_error is not None:
            raise self._queued_object_error
        if self._queued_object is not None:
            return self._queued_object
        raise DBusException(f"no object queued for {bus_name}{object_path}")


class Interface:
    """Stand-in for dbus.proxies.Interface.

    Real DBus methods are reached through attribute access, which the real
    ``Interface.__getattr__`` forwards to ``get_dbus_method``.  This fake
    forwards to a ``Get`` method on the wrapped object directly, matching
    how ``org.freedesktop.DBus.Properties.Get`` is actually invoked by
    callers: ``props.Get(interface, property_name)``.
    """

    def __init__(self, obj: Any, dbus_interface: str) -> None:
        self._obj = obj
        self._dbus_interface = dbus_interface

    def Get(self, _interface: str, prop_name: str) -> Any:  # noqa: N802 - DBus method name.
        return getattr(self._obj, "properties", {})[prop_name]


class MainLoop:
    """Stand-in for gi.repository.GLib.MainLoop."""

    def run(self) -> None:
        return None


def install() -> None:
    """Register dbus + gi stand-ins in sys.modules."""
    if "dbus" in sys.modules:
        return

    dbus = types.ModuleType("dbus")
    dbus.SessionBus = Bus
    dbus.SystemBus = Bus
    dbus.DBusException = DBusException
    dbus.Interface = Interface

    mainloop = types.ModuleType("dbus.mainloop")
    glib = types.ModuleType("dbus.mainloop.glib")

    def dbus_gmainloop(*, set_as_default: bool = False) -> None:
        return None

    glib.DBusGMainLoop = dbus_gmainloop
    mainloop.glib = glib
    dbus.mainloop = mainloop

    gi = types.ModuleType("gi")
    gi.__path__ = []
    gi_repository = types.ModuleType("gi.repository")
    gi_repository.GLib = types.SimpleNamespace(MainLoop=MainLoop)
    gi.repository = gi_repository

    sys.modules["dbus"] = dbus
    sys.modules["dbus.mainloop"] = mainloop
    sys.modules["dbus.mainloop.glib"] = glib
    sys.modules["gi"] = gi
    sys.modules["gi.repository"] = gi_repository
