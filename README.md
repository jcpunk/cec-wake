# cec-wake

Systemd user service that monitors the desktop screensaver over DBus and sends
an HDMI-CEC **Active Source** command when the screen unlocks, waking an
attached TV or display.

## How it works

`cec_wake_daemon` subscribes to `ActiveChanged` signals from all common
screensaver DBus interfaces (GNOME, KDE, Cinnamon, freedesktop).  When the
signal fires with `is_active=False` (unlock), it invokes `cec-client` with
`as\nquit\n` (Active Source + exit).  Active Source is preferred over
`on 0` because it does not assume the TV occupies logical address 0 in all
HDMI topologies.

A udev rule (`99-cec.rules`) creates `/dev/cec` as a stable symlink for any
USB CEC adapter whose product string contains "CEC" and grants seat-local write
access via `uaccess`, so no supplemental groups are required.

The daemon is a **systemd user unit**, runs as the logged-in user, and
integrates with `sd_notify` for `Type=notify`-style readiness signalling.

## Files

| File | Installed path | Purpose |
|------|---------------|---------|
| `cec_wake_daemon.py` | `/usr/libexec/cec_wake_daemon` | Main daemon |
| `cec-wake.service` | `/usr/lib/systemd/user/cec-wake.service` | Systemd user unit |
| `99-cec.rules` | `/usr/lib/udev/rules.d/99-cec.rules` | Udev symlink + permissions |
| `cec-wake.spec` | — | RPM spec |

## Requirements

All packages are available in RHEL/AlmaLinux base repos or EPEL:

| Package | Provides |
|---------|---------|
| `cec-utils` | `/usr/bin/cec-client` |
| `python3-dbus` | DBus session bus subscription |
| `python3-gobject` | GLib main loop |
| `python3-sdnotify` | `sd_notify` integration |
| `systemd`, `udev` | Service and device management |

## Installation

### RPM (recommended)

```bash
# Build from a source archive tagged v0.1.0
rpmbuild -ba cec-wake.spec

# Install
sudo dnf install ./cec-wake-0.1.0-1.<dist>.noarch.rpm

# Enable and start for your user session
systemctl --user daemon-reload
systemctl --user enable --now cec-wake.service
```

### Manual

```bash
install -D -m 0755 cec_wake_daemon.py ~/.local/bin/cec_wake_daemon.py
install -D -m 0644 cec-wake.service \
    ~/.config/systemd/user/cec-wake.service

# Udev rule requires root
sudo install -D -m 0644 99-cec.rules \
    /usr/lib/udev/rules.d/99-cec.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb

systemctl --user daemon-reload
systemctl --user enable --now cec-wake.service
```

After installing the udev rule, replug the CEC adapter so the symlink and
`uaccess` tag are applied.

## Configuration

The daemon accepts command-line arguments.  Override them in the service unit
via a drop-in:

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
| `--adapter PATH` | `/dev/cec` | CEC device node |
| `--device-timeout SECONDS` | `120` | Seconds to wait for the device at startup |
| `--wake-on-start` | off | Send an Active Source command immediately after startup |
| `--debug` | off | Enable debug logging |

## Screensaver interfaces monitored

- `org.freedesktop.ScreenSaver`
- `org.gnome.ScreenSaver`
- `org.kde.screensaver`
- `org.cinnamon.ScreenSaver`

Interfaces not present on the running desktop are skipped silently.  The
daemon exits if none can be subscribed.

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
echo -e "as\nquit" | cec-client -s /dev/cec
```

If `/dev/cec` does not appear after replugging, check that the product string
contains "CEC":

```bash
udevadm info --query=all --name=<device> | grep PRODUCT
```

## Design notes

**Why a user unit?** The daemon subscribes to the *session* DBus, which is
only reachable from within a user session.  A system unit cannot subscribe to
per-user session buses portably.

**Why `as` instead of `on 0`?** Active Source broadcasts to all CEC devices
and does not require knowing the TV's logical address, which varies by
topology.

**Why synchronous `subprocess.run`?** `cec-client` completes in under two
seconds.  GLib dispatches one signal callback at a time.  A threading lock
drops duplicate `ActiveChanged(False)` signals that arrive while a call is
in flight.  The added complexity of async dispatch is not justified.

**Why `uaccess` instead of a supplemental group?** `uaccess` is the
systemd-recommended mechanism for seat-local device access.  It requires no
group membership changes and is revoked when the user's session ends.

## License

GPL-3.0-or-later
