"""Install in-memory stubs for the daemon's optional runtime dependencies.

``cec_wake_daemon`` imports ``python3-pywayland`` (required) and
``python3-dbus`` / ``python3-gobject`` (optional, guarded) at import time.
These stubs let the unit tests import and exercise the daemon on a machine
that has not installed the runtime dependency set, so the test suite has no
external system requirements beyond the standard library.

Import this module and call :func:`install` before importing
``cec_wake_daemon``.  Installation is idempotent.
"""

import sys
import types


def _register(name: str) -> types.ModuleType:
    """Return (creating if needed) a module registered in sys.modules."""
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    return module


def install() -> None:
    """Register stub modules for pywayland, dbus, and gi if missing."""
    if getattr(install, "_done", False):
        return
    install._done = True

    # -- python3-pywayland (required import) -------------------------------
    if "pywayland" not in sys.modules:
        pywayland = _register("pywayland")

        client = _register("pywayland.client")

        class Display:
            """Stand-in for pywayland.client.Display."""

            def connect(self, *args, **kwargs):
                return None

            def disconnect(self, *args, **kwargs):
                return None

            def get_registry(self, *args, **kwargs):
                return None

            def roundtrip(self, *args, **kwargs):
                return 0

            def dispatch(self, *args, **kwargs):
                return -1

        client.Display = Display

        ext_idle = _register("pywayland.protocol.ext_idle_notify_v1")
        ext_idle.ExtIdleNotifierV1 = type("ExtIdleNotifierV1", (), {})

        wl_wayland = _register("pywayland.protocol.wayland")
        wl_wayland.WlSeat = type("WlSeat", (), {})
        wl_wayland.WlOutput = type("WlOutput", (), {})

        wlr = _register(
            "pywayland.protocol.wlr_output_power_management_unstable_v1"
        )
        wlr.ZwlrOutputPowerManagerV1 = type("ZwlrOutputPowerManagerV1", (), {})

        protocol = _register("pywayland.protocol")
        protocol.ext_idle_notify_v1 = ext_idle
        protocol.wayland = wl_wayland
        protocol.wlr_output_power_management_unstable_v1 = wlr

    # -- python3-dbus (optional) -------------------------------------------
    if "dbus" not in sys.modules:
        dbus = _register("dbus")

        class DBusException(Exception):
            """Stand-in for dbus.DBusException."""

        class Bus:
            """Stand-in for a D-Bus connection.

            ``add_signal_receiver`` records the handlers that were
            registered so tests can invoke them.  ``get_object`` raises so
            callers that expect a bus failure exercise their except branch.
            """

            def __init__(self):
                self.receivers = []

            def add_signal_receiver(self, handler, *args, **kwargs):
                self.receivers.append(handler)
                return None

            def get_object(self, *args, **kwargs):
                raise DBusException("no bus in tests")

        dbus.SessionBus = Bus
        dbus.SystemBus = Bus
        dbus.DBusException = DBusException

        def make_interface(obj, _signature):
            """Return a properties object reading obj.idle_hint."""

            class _Interface:
                def Get(self, _iface, property):
                    return getattr(obj, "idle_hint", False)

            return _Interface()

        dbus.Interface = make_interface

        mainloop = _register("dbus.mainloop")
        dbus.mainloop = mainloop
        glib = _register("dbus.mainloop.glib")

        class MainLoop:
            def run(self, *args, **kwargs):
                return None

        def dbus_gmainloop(*args, **kwargs):
            return MainLoop()

        glib.DBusGMainLoop = dbus_gmainloop
        mainloop.glib = glib

    # -- python3-gobject / gi (optional) -----------------------------------
    if "gi" not in sys.modules:
        gi = _register("gi")
        gi.__path__ = []
        gi_repository = _register("gi.repository")
        gi.repository = gi_repository

        class GLib:
            """Stand-in for gi.repository.GLIB."""

            class MainLoop:
                def __init__(self, *args, **kwargs):
                    pass

                def run(self, *args, **kwargs):
                    return None

        # Attribute name is "GLib" (camelCase), matching gi.repository.
        setattr(gi_repository, "GLib", GLib)
