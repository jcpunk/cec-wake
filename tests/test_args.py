"""Tests for environment-default argument parsing."""

import sys

import cec_wake_daemon as cec

_ENV_KEYS = (
    "CEC_WAKE_DEBUG",
    "CEC_WAKE_ADAPTER",
    "CEC_WAKE_DEVICE_TIMEOUT",
    "CEC_WAKE_HDMI_PORT",
    "CEC_WAKE_IDLE_TIMEOUT",
    "CEC_WAKE_OSD_NAME",
    "CEC_WAKE_WAKE_ON_START",
    "CEC_WAKE_NO_WAYLAND",
    "CEC_WAKE_NO_DBUS",
)


def _clean_env(monkeypatch):
    """Remove every CEC_WAKE_* env var so defaults are observed."""
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_parse_args_defaults(monkeypatch):
    """All flags default to the documented built-in values."""
    _clean_env(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog"])
    args = cec.parse_args()
    assert args.debug is False
    assert args.adapter == "/dev/cec"
    assert args.device_timeout == 120
    assert args.hdmi_port == 0
    assert args.idle_timeout_sec == 60
    assert args.osd_name == ""
    assert args.wake_on_start is False
    assert args.no_wayland is False
    assert args.no_dbus is False


def test_parse_args_bool_env(monkeypatch):
    """A CEC_WAKE_DEBUG=1 env var turns the flag on."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_DEBUG", "1")
    monkeypatch.setattr(sys, "argv", ["prog"])
    assert cec.parse_args().debug is True


def test_parse_args_int_env(monkeypatch):
    """An integer env var is parsed as int."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_IDLE_TIMEOUT", "30")
    monkeypatch.setattr(sys, "argv", ["prog"])
    assert cec.parse_args().idle_timeout_sec == 30


def test_parse_args_bool_env_variants(monkeypatch):
    """'true' and 'yes' both enable their flags."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_NO_WAYLAND", "true")
    monkeypatch.setenv("CEC_WAKE_NO_DBUS", "yes")
    monkeypatch.setattr(sys, "argv", ["prog"])
    args = cec.parse_args()
    assert args.no_wayland is True
    assert args.no_dbus is True


def test_parse_args_cli_overrides_env(monkeypatch):
    """CLI arguments take precedence over environment defaults."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_DEBUG", "0")
    monkeypatch.setenv("CEC_WAKE_ADAPTER", "/dev/env")
    monkeypatch.setattr(
        sys, "argv", ["prog", "--debug", "--adapter", "/dev/cli"]
    )
    args = cec.parse_args()
    assert args.debug is True
    assert args.adapter == "/dev/cli"


def test_parse_args_int_flags(monkeypatch):
    """Integer flags parse from the command line."""
    monkeypatch.setattr(
        sys, "argv",
        ["prog", "--device-timeout", "5", "--hdmi-port", "3", "--osd-name", "PC"],
    )
    args = cec.parse_args()
    assert args.device_timeout == 5
    assert args.hdmi_port == 3
    assert args.osd_name == "PC"
