# Design and rationale

`src/cec_wake_daemon.py` sends an HDMI-CEC Power-On + Active-Source command when an
attached display powers back on.  The daemon subscribes to several
complementary wake-event sources, all of which are optional at runtime.  It
starts with whatever subset is available and logs which sources are active.

## Wake-event sources

All sources share a single non-blocking lock, so only one `cec-client`
invocation runs at a time.  Events arriving while a wake is in flight are
silently dropped; the in-flight call already sent the command.

### Wayland sources (`python3-pywayland`)

1. `ext-idle-notify-v1` -- the current KDE/Wayland mechanism.  The daemon
   registers an idle notification with a fixed timeout (default 60s, well
   below any practical screen-off setting).  The compositor fires `idled`
   after the configured timeout of continuous user inactivity, then fires
   `resumed` when activity is detected.  Because the notification resets to
   active state after each `resumed` event, spurious wakes during normal use
   are impossible regardless of how short the timeout is.  The timeout only
   needs to be shorter than the display power-off setting so that `idled`
   fires before the screen goes dark, arming the object for `resumed` on wake.

2. `zwlr-output-power-management-v1` -- emits a `mode` event directly when
   display power changes (on/off).  Currently not advertised by KWin 6.x, but
   included so the daemon automatically benefits from it if KDE adds support
   in a future release.  No configuration required; fires on actual DPMS state
   transitions.

### DBus sources (`python3-dbus` + `python3-gobject`)

3. Screensaver `ActiveChanged` / `SessionIdleChanged` (session bus) -- covers
   screen lock/unlock wake events on GNOME, Cinnamon, and KDE when the screen
   locker is active.  Not emitted by KDE 6.x for DPMS-only idle without a
   lock; the Wayland path handles that case.

4. logind `IdleHint` `PropertiesChanged` (system bus) -- fires when the logind
   session `IdleHint` transitions `True -> False`, indicating the session
   resumed from idle.  Reliable on X11 sessions and compositors that report
   idle state to logind.  Not used by KDE 6.x on Wayland (IdleHint never
   transitions in that configuration).

5. logind `PrepareForSleep` (system bus) -- fires with argument `False` when
   the system resumes from suspend.  Covers the case where the system
   suspends during an idle period, bypassing the normal idle -> resume event
   sequence.

## Runtime dependencies

- `python3-pywayland` -- Wayland protocol bindings (sources 1, 2).
- `python3-dbus` -- DBus signal subscription (sources 3-5).
- `python3-gobject` -- GLib main loop for DBus (sources 3-5).
- `cec-utils` -- provides `/usr/bin/cec-client`.

`sd_notify` is implemented inline, so `python3-sdnotify` is not required.

## Configuration

All options have corresponding `CEC_WAKE_*` environment variables, so the
daemon can be configured via an `EnvironmentFile` without touching the service
unit.  Command-line arguments always take precedence over environment
variables.  See `configs/cec-wake.conf` for the full, documented list.

## systemd unit

The service is a **systemd user unit** that runs as the logged-in user.  The
Wayland display name is auto-discovered at runtime from `$XDG_RUNTIME_DIR`
(set by systemd for user services), so no `WAYLAND_DISPLAY` is needed and no
unit edit is required.  Pin a specific display only if you must, via a
drop-in:

```bash
systemctl --user edit cec-wake.service
```

```ini
[Service]
Environment=WAYLAND_DISPLAY=wayland-1
```

## Design decisions

- **Why a user unit?** The daemon subscribes to the *session* DBus, which is
  only reachable from within a user session.  A system unit cannot subscribe
  to per-user session buses portably.

- **Why `as` (Active Source) instead of `on 0`?** Active Source broadcasts to
  all CEC devices and does not require knowing the TV's logical address,
  which varies by topology.

- **Why synchronous `subprocess.run`-style invocation?** `cec-client`
  completes in under two seconds.  The wake runs on its own daemon thread so
  blocking inside libcec's USB adapter open path cannot starve the Wayland
  event loop of keepalives (which would make the compositor drop the
  connection).

- **Why `uaccess` instead of a supplemental group?** `uaccess` is the
  systemd-recommended mechanism for seat-local device access.  It requires no
  group membership changes and is revoked when the user's session ends.

## Logind session path encoding

The logind object path for a session is derived from `XDG_SESSION_ID` by
replacing each character outside `[A-Za-z0-9_]` with `'_'` followed by its
two-hex-digit ASCII value.  For numeric IDs (the common case) this yields
`/org/freedesktop/login1/session/_3<digits>` (e.g. session "2" -> "_32").
