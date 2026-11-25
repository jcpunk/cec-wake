"""Invoke cec-client to send CEC wake commands."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess

CEC_CLIENT = "/usr/bin/cec-client"

CEC_WAKE_CMD = b"on 0\nquit\n"
CEC_SELECT_CMD = b"as\nquit\n"

LOG = logging.getLogger("cec-wake")

__all__ = ["CEC_CLIENT", "run_cec_wake"]


def _run_cec_cmd(cmd: list[str], cec_input: bytes, label: str) -> bool:
    """
    Run cec-client with the given stdin payload and return True on success.

    Must be called from a worker thread, not the Wayland event loop thread.
    On timeout the entire process group is SIGKILL'd to release the USB
    CEC adapter before returning.
    """
    LOG.info("Sending CEC %s command", label)
    LOG.debug("Command: %s  stdin: %s", cmd, cec_input)
    try:
        proc = subprocess.Popen(  # noqa: S603 - cec-client is the target.
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(input=cec_input, timeout=10)
        except subprocess.TimeoutExpired:
            LOG.error(  # noqa: TRY400
                "cec-client timed out during %s; killing process group", label
            )
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()
            return False
        if proc.returncode != 0:
            LOG.warning(
                "cec-client exited %d during %s: %s",
                proc.returncode,
                label,
                stderr.decode(errors="replace").strip(),
            )
            return False
    except OSError as exc:
        LOG.error(  # noqa: TRY400
            "Failed to run cec-client during %s: %s", label, exc
        )
        return False
    else:
        LOG.debug(
            "cec-client %s output: %s",
            label,
            stdout.decode(errors="replace").strip(),
        )
        return True


def run_cec_wake(hdmi_port: int = 0, osd_name: str = "") -> None:
    """
    Send Power-On then Active-Source CEC commands via cec-client.

    Must be called from a dedicated thread, NOT the Wayland event loop
    thread.  cec-client can block inside libcec's USB adapter open path;
    blocking the event loop prevents Wayland keepalives from being sent,
    which can cause the compositor to drop the connection.

    No explicit adapter path is passed to cec-client; libcec auto-detects
    the Pulse-Eight USB adapter via USB enumeration.  An explicit path would
    be treated as a serial port, which fails on USB character devices.
    """
    cmd = [CEC_CLIENT, "-s"]
    if hdmi_port:
        cmd += ["-p", str(hdmi_port)]
    if osd_name:
        cmd += ["-o", osd_name]

    if not _run_cec_cmd(cmd, CEC_WAKE_CMD, "Power-On"):
        return
    _run_cec_cmd(cmd, CEC_SELECT_CMD, "Active-Source")
