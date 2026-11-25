"""Tests for the single-flight wake dispatcher."""

from __future__ import annotations

import threading
from unittest.mock import patch

from cec_wake import dispatcher as dispatcher_mod


def test_dispatch_runs_worker_once():
    """dispatch hands the wake to exactly one worker thread."""
    calls = []
    started = threading.Event()
    release = threading.Event()

    def fake_wake(*_args, **_kwargs):
        calls.append(1)
        started.set()
        release.wait(3)

    with patch.object(dispatcher_mod, "run_cec_wake", side_effect=fake_wake):
        dispatch = dispatcher_mod.build_wake_dispatcher()
        dispatch("source")
        assert started.wait(2), "worker thread never started"
        release.set()
        for thread in threading.enumerate():
            if thread.name == "cec-wake":
                thread.join(2)

    assert len(calls) == 1


def test_dispatch_drops_event_while_in_flight():
    """A second dispatch during an in-flight wake is dropped, not queued."""
    calls = []
    started = threading.Event()
    release = threading.Event()

    def fake_wake(*_args, **_kwargs):
        calls.append(1)
        started.set()
        release.wait(3)

    with patch.object(dispatcher_mod, "run_cec_wake", side_effect=fake_wake):
        dispatch = dispatcher_mod.build_wake_dispatcher()
        dispatch("source-a")
        assert started.wait(2), "worker thread never started"
        # Lock is held by the in-flight worker; this must be dropped.
        dispatch("source-b")
        release.set()
        for thread in threading.enumerate():
            if thread.name == "cec-wake":
                thread.join(2)

    assert len(calls) == 1
