# cec-wake

Systemd user service that sends an HDMI-CEC **Power-On + Active-Source**
command when an attached display comes back on, waking the TV and switching
it to the PC's input.

## How it works

`cec_wake` monitors several independent, all-optional wake-event sources and
dispatches a CEC wake through whichever subset is available on the running
desktop:

- **Wayland** (`ext-idle-notify-v1`, `zwlr-output-power-management-v1`) --
  the primary path on KDE/Wayland.
- **DBus** -- screensaver `ActiveChanged`/`SessionIdleChanged`, logind
  `IdleHint` transitions, and logind `PrepareForSleep` (system resume).

All sources share a single non-blocking lock, so only one `cec-client`
invocation runs at a time; events arriving mid-wake are dropped, not queued.
Full rationale for each source lives in `docs/DESIGN.md`.

A udev rule (`99-cec.rules`) creates `/dev/cec` as a stable symlink for any
USB CEC adapter whose product string contains "CEC" and grants seat-local
write access via `uaccess`, so no supplemental groups are required.

The daemon is a **systemd user unit**, runs as the logged-in user, and
integrates with `sd_notify` for `Type=notify`-style readiness and watchdog
signalling.

## Files

| Path | Installed path | Purpose |
|------|-----------------|---------|
| `src/cec_wake/` | `/usr/libexec/cec_wake_daemon` | Daemon source, packaged as a zipapp |
| `units/cec-wake.service` | `/usr/lib/systemd/user/cec-wake.service` | Systemd user unit |
| `units/99-cec.rules` | `/usr/lib/udev/rules.d/99-cec.rules` | Udev symlink + permissions |
| `configs/cec-wake.conf` | `/usr/share/doc/cec-wake/cec-wake.conf` | Documented `EnvironmentFile` template |
| `cec-wake.spec` | -- | RPM spec |

The daemon is packaged as a single-file Python
[zipapp](https://docs.python.org/3/library/zipapp.html) rather than installed
into site-packages.  This keeps it independent of the build host's Python
minor version, which matters when one RPM must run unmodified across several
concurrently supported RHEL/AlmaLinux major versions.

## Requirements

All packages are available in RHEL/AlmaLinux base repos or EPEL:

| Package | Provides | Required? |
|---------|----------|-----------|
| `cec-utils` | `/usr/bin/cec-client` | Yes |
| `python3` | Interpreter (>=3.9) | Yes |
| `python3-pywayland` | Wayland wake sources | Optional; degrades to a logged warning |
| `python3-dbus`, `python3-gobject` | DBus wake sources | Optional; degrades to a logged warning |
| `systemd`, `udev` | Service and device management | Yes |

`sd_notify` is implemented inline, so no `python3-sdnotify` dependency is
needed.

## Installation

### RPM (recommended)

```bash
make sources
make rpm
sudo dnf install ./RPMS/noarch/cec-wake-0.1.0-1.<dist>.noarch.rpm

systemctl --user daemon-reload
systemctl --user enable --now cec-wake.service
```

### Manual

```bash
make zipapp
install -D -m 0755 cec_wake_daemon ~/.local/libexec/cec_wake_daemon
install -D -m 0644 units/cec-wake.service \
    ~/.config/systemd/user/cec-wake.service
# Point ExecStart at the installed path if it differs from /usr/libexec:
#   systemctl --user edit cec-wake.service

# Udev rule requires root
sudo install -D -m 0644 units/99-cec.rules \
    /usr/lib/udev/rules.d/99-cec.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb

systemctl --user daemon-reload
systemctl --user enable --now cec-wake.service
```

After installing the udev rule, replug the CEC adapter so the symlink and
`uaccess` tag are applied.

## Configuration

Every option has a `CEC_WAKE_*` environment variable, so the daemon can be
configured via an `EnvironmentFile` without touching the unit.  See
`configs/cec-wake.conf` for the full, documented list.  CLI arguments always
take precedence over environment variables:

```bash
systemctl --user edit cec-wake.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/libexec/cec_wake_daemon --adapter /dev/cec1 --wake-on-start
```

| Option | Default | Description |
|--------|---------|-------------|
| `--adapter PATH` | `/dev/cec` | CEC device node to check for at startup |
| `--device-timeout SECONDS` | `120` | Seconds to wait for the device at startup |
| `--hdmi-port N` | `0` (auto) | CEC physical address via `cec-client -p` |
| `--idle-timeout-sec SECONDS` | `60` | `ext-idle-notify-v1` idle timeout |
| `--osd-name NAME` | libcec default | Cosmetic OSD name broadcast to the TV |
| `--wake-on-start` | off | Send a CEC wake shortly after startup |
| `--no-wayland` | off | Disable Wayland wake sources |
| `--no-dbus` | off | Disable DBus wake sources |
| `--debug` | off | Enable debug logging |

## Troubleshooting

Check service status and logs:

```bash
systemctl --user status cec-wake.service
journalctl --user -u cec-wake.service -f
```

Verify the device symlink and permissions:

```bash
ls -l /dev/cec
# Confirm the adapter is accessible (exit 0 = writable)
test -w /dev/cec && echo ok
```

Test CEC manually:

```bash
echo -e "on 0\nas\nquit" | cec-client -s
```

If `/dev/cec` does not appear after replugging, check that the product
string contains "CEC":

```bash
udevadm info --query=all --name=<device> | grep PRODUCT
```

## Design notes

See `docs/DESIGN.md` for the full rationale behind each wake source,
runtime dependency, and packaging decision.  In short:

**Why a user unit?** The daemon subscribes to the *session* DBus and the
per-session Wayland socket, both of which are only reachable from within a
user session.

**Why Power-On then Active Source?** Power-On wakes a TV that is fully off;
Active Source then claims the input without needing to know the TV's
logical address, which varies by HDMI topology.

**Why `uaccess` instead of a supplemental group?** `uaccess` is the
systemd-recommended mechanism for seat-local device access.  It requires no
group membership changes and is revoked when the user's session ends.

## Development

```bash
uv sync --group dev
uv run pytest       # unit tests, coverage gate at 97%
uv run ruff check . # lint
uv run mypy         # type-check src/
```

## License

GPL-3.0-or-later
