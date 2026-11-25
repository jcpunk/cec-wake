"""Pytest configuration for the cec-wake test suite.

Puts the source directory (so ``cec_wake_daemon`` is importable) and the tests
directory (so the shared stub helper is importable) onto ``sys.path``, then
installs the dependency stubs *before* any test module imports the package
under test.

The daemon is a single-module script shipped under ``src/``; the tests import
it as a plain top-level module rather than turning ``src/`` into a package.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SRC = os.path.join(_ROOT, "src")
for _path in (_SRC, _ROOT, _HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import deps_stub  # noqa: E402  (path bootstrap precedes these imports)

deps_stub.install()
