"""Tests for environment-default argument parsing."""

from __future__ import annotations

from cec_wake import config as config_mod

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
    config = config_mod.parse_args([])
    assert config.debug is False
    assert config.adapter == "/dev/cec"
    assert config.device_timeout == 120
    assert config.hdmi_port == 0
    assert config.idle_timeout_sec == 60
    assert config.osd_name == ""
    assert config.wake_on_start is False
    assert config.no_wayland is False
    assert config.no_dbus is False


def test_parse_args_bool_env(monkeypatch):
    """A CEC_WAKE_DEBUG=1 env var turns the flag on."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_DEBUG", "1")
    assert config_mod.parse_args([]).debug is True


def test_parse_args_int_env(monkeypatch):
    """An integer env var is parsed as int."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_IDLE_TIMEOUT", "30")
    assert config_mod.parse_args([]).idle_timeout_sec == 30


def test_parse_args_bool_env_variants(monkeypatch):
    """'true' and 'yes' both enable their flags."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_NO_WAYLAND", "true")
    monkeypatch.setenv("CEC_WAKE_NO_DBUS", "yes")
    config = config_mod.parse_args([])
    assert config.no_wayland is True
    assert config.no_dbus is True


def test_parse_args_cli_overrides_env(monkeypatch):
    """CLI arguments take precedence over environment defaults."""
    _clean_env(monkeypatch)
    monkeypatch.setenv("CEC_WAKE_DEBUG", "0")
    monkeypatch.setenv("CEC_WAKE_ADAPTER", "/dev/env")
    config = config_mod.parse_args(["--debug", "--adapter", "/dev/cli"])
    assert config.debug is True
    assert config.adapter == "/dev/cli"


def test_parse_args_int_flags():
    """Integer flags parse from the command line."""
    config = config_mod.parse_args(
        ["--device-timeout", "5", "--hdmi-port", "3", "--osd-name", "PC"]
    )
    assert config.device_timeout == 5
    assert config.hdmi_port == 3
    assert config.osd_name == "PC"
