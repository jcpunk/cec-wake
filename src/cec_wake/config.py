"""Command-line/environment-variable configuration for the daemon."""

from __future__ import annotations

import os
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from dataclasses import dataclass

__all__ = ["Config", "parse_args"]


@dataclass(frozen=True)
class Config:
    """Resolved daemon configuration, after CLI/environment merge."""

    debug: bool
    adapter: str
    device_timeout: int
    hdmi_port: int
    idle_timeout_sec: int
    osd_name: str
    wake_on_start: bool
    no_wayland: bool
    no_dbus: bool


def _bool_env(key: str) -> bool:
    value = os.getenv(key, "").strip().lower()
    return value in ("1", "true", "yes")


def parse_args(argv: list[str] | None = None) -> Config:
    """
    Parse arguments, with environment variables as defaults.

    CLI arguments always take precedence over environment variables.
    """
    parser = ArgumentParser(
        description=__doc__,
        formatter_class=RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=_bool_env("CEC_WAKE_DEBUG"),
        help="Enable debug logging [env: CEC_WAKE_DEBUG]",
    )
    parser.add_argument(
        "--adapter",
        default=os.getenv("CEC_WAKE_ADAPTER", "/dev/cec"),
        metavar="PATH",
        help=(
            "CEC device path to check for at startup (default: /dev/cec). "
            "Not passed to cec-client; libcec auto-detects the adapter "
            "[env: CEC_WAKE_ADAPTER]"
        ),
    )
    parser.add_argument(
        "--device-timeout",
        type=int,
        default=int(os.getenv("CEC_WAKE_DEVICE_TIMEOUT", "120")),
        metavar="SECONDS",
        help=(
            "Seconds to wait for CEC device at startup (default: 120) "
            "[env: CEC_WAKE_DEVICE_TIMEOUT]"
        ),
    )
    parser.add_argument(
        "--hdmi-port",
        type=int,
        default=int(os.getenv("CEC_WAKE_HDMI_PORT", "0")),
        metavar="N",
        help=(
            "HDMI port number the PC is connected to (1-15). "
            "Sets the CEC physical address via cec-client -p, bypassing "
            "DRM-based auto-detection which can fail on nvidia systems when "
            "the GPU enumerates as card1 rather than card0. "
            "If 0, libcec auto-detects (default: 0) [env: CEC_WAKE_HDMI_PORT]"
        ),
    )
    parser.add_argument(
        "--idle-timeout-sec",
        type=int,
        default=int(os.getenv("CEC_WAKE_IDLE_TIMEOUT", "60")),
        metavar="SECONDS",
        help=(
            "Idle timeout for ext-idle-notify-v1, in seconds (default: 60). "
            "Must be less than the KDE display power-off setting so that the "
            "idled event fires before the screen goes dark, arming the "
            "notification for resumed on wake.  Spurious wakes cannot occur "
            "because the notification resets after each resumed event. "
            "[env: CEC_WAKE_IDLE_TIMEOUT]"
        ),
    )
    parser.add_argument(
        "--osd-name",
        default=os.getenv("CEC_WAKE_OSD_NAME", ""),
        metavar="NAME",
        help=(
            "OSD name broadcast to the TV via CEC SetOSDName (max 14 chars, "
            "ASCII printable).  Purely cosmetic; omit to use libcec's default "
            "[env: CEC_WAKE_OSD_NAME]"
        ),
    )
    parser.add_argument(
        "--wake-on-start",
        action="store_true",
        default=_bool_env("CEC_WAKE_WAKE_ON_START"),
        help=(
            "Send a CEC wake command shortly after startup "
            "[env: CEC_WAKE_WAKE_ON_START]"
        ),
    )
    parser.add_argument(
        "--no-wayland",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_WAYLAND"),
        help=(
            "Disable Wayland event sources (ext-idle-notify-v1, "
            "zwlr-output-power-management-v1). "
            "Use on X11 sessions or if Wayland monitoring causes issues "
            "[env: CEC_WAKE_NO_WAYLAND]"
        ),
    )
    parser.add_argument(
        "--no-dbus",
        action="store_true",
        default=_bool_env("CEC_WAKE_NO_DBUS"),
        help=(
            "Disable DBus event sources (screensaver, logind IdleHint, "
            "PrepareForSleep). "
            "Use if DBus monitoring causes spurious wakes "
            "[env: CEC_WAKE_NO_DBUS]"
        ),
    )
    args = parser.parse_args(argv)
    # Config field names match argparse dest names exactly (by convention,
    # kept in sync with the --flags above), so vars(args) can be splatted
    # directly instead of repeating every field name here.
    return Config(**vars(args))
