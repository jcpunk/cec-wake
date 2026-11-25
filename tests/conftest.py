"""Pytest configuration for the cec-wake test suite.

Puts the source directory onto ``sys.path`` (so ``cec_wake`` is importable
without an editable install), then installs the dependency stubs *before*
any test module imports the package under test.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from tests.fixtures import dbus_stub, pywayland_stub  # noqa: E402

pywayland_stub.install()
dbus_stub.install()
