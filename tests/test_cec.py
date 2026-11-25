"""Tests for cec-client invocation and the wake command builder."""

import signal
import subprocess

from unittest.mock import Mock, patch

import cec_wake_daemon as cec


def test_run_cec_cmd_success():
    """A zero-exit cec-client run returns True."""
    proc = Mock()
    proc.communicate.return_value = (b"ok", b"")
    proc.returncode = 0
    with patch.object(cec.subprocess, "Popen", return_value=proc):
        assert cec._run_cec_cmd([cec.CEC_CLIENT], b"x", "Power-On") is True


def test_run_cec_cmd_nonzero_returns_false():
    """A non-zero exit code is reported as failure."""
    proc = Mock()
    proc.communicate.return_value = (b"", b"boom")
    proc.returncode = 3
    with patch.object(cec.subprocess, "Popen", return_value=proc):
        assert cec._run_cec_cmd([cec.CEC_CLIENT], b"x", "x") is False


def test_run_cec_cmd_timeout_kills_group():
    """A timeout kills the process group and returns False."""
    proc = Mock()
    proc.communicate.side_effect = subprocess.TimeoutExpired(
        cmd=[cec.CEC_CLIENT], timeout=10
    )
    with (
        patch.object(cec.subprocess, "Popen", return_value=proc),
        patch.object(cec.os, "getpgid", return_value=999) as getpgid,
        patch.object(cec.os, "killpg") as killpg,
        patch.object(proc, "wait") as pwait,
    ):
        assert cec._run_cec_cmd([cec.CEC_CLIENT], b"x", "x") is False
    getpgid.assert_called_once_with(proc.pid)
    killpg.assert_called_once_with(999, signal.SIGKILL)
    pwait.assert_called_once()


def test_run_cec_cmd_oserror_returns_false():
    """An OSError from Popen is swallowed and reported as failure."""
    with patch.object(cec.subprocess, "Popen", side_effect=OSError("no binary")):
        assert cec._run_cec_cmd([cec.CEC_CLIENT], b"x", "x") is False


def test_run_cec_wake_default_cmd():
    """Defaults produce the bare client invocation."""
    with patch.object(cec, "_run_cec_cmd") as run:
        cec.run_cec_wake()
    assert run.call_args_list[0].args[0] == [cec.CEC_CLIENT, "-s"]


def test_run_cec_wake_includes_port_and_name():
    """Port and OSD name are threaded through to the client command."""
    cmd = None

    def capture(command, _input, _label):
        nonlocal cmd
        cmd = command
        return True

    with patch.object(cec, "_run_cec_cmd", side_effect=capture):
        cec.run_cec_wake(hdmi_port=2, osd_name="PC")
    assert "-p" in cmd and "2" in cmd and "-o" in cmd and "PC" in cmd


def test_run_cec_wake_sends_power_then_active_source():
    """The wake sends Power-On then Active-Source, in order."""
    order = []

    def fake_run(command, cec_input, label):
        order.append(label)
        return True

    with patch.object(cec, "_run_cec_cmd", side_effect=fake_run):
        cec.run_cec_wake()
    assert order == ["Power-On", "Active-Source"]


def test_run_cec_wake_short_circuits_on_failure():
    """Active-Source is not sent if Power-On fails."""
    order = []

    def fake_run(command, cec_input, label):
        order.append(label)
        return label != "Power-On"

    with patch.object(cec, "_run_cec_cmd", side_effect=fake_run):
        cec.run_cec_wake()
    assert order == ["Power-On"]
