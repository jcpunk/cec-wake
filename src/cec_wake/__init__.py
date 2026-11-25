"""cec_wake - HDMI-CEC wake controller for Linux desktops.

Sends a CEC Power-On + Active-Source command when the display comes back on.

Wake sources are all optional at runtime and share one non-blocking lock so
only a single cec-client invocation runs at a time.  Sources covered:

  * Wayland -- ext-idle-notify-v1 and zwlr-output-power-management-v1
  * DBus    -- screensaver ActiveChanged/SessionIdleChanged, logind
               IdleHint PropertiesChanged, and logind PrepareForSleep

Full design rationale (wake sources, runtime dependencies, unit layout) lives
in docs/DESIGN.md.
"""

from __future__ import annotations

__version__ = "0.1.0"
