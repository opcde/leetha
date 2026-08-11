"""Learning-window saturation logic for the automatic baseline.

The window closes when leetha stops discovering devices, not on a clock.

A fixed duration cannot serve leetha's real usage. Sessions range from a
one-hour assessment run to a multi-week deployment; any fixed window either
never closes for the short runs -- leaving new_host pinned at INFO forever, so
the severity ladder never activates -- or misfits the long ones. Saturation
scales to *network size* rather than session length: a 20-device home network
goes quiet in minutes, a 500-device corporate network takes days, and the same
rule covers both without a mode switch.
"""
from __future__ import annotations

from datetime import datetime, timedelta

#: Fraction of total observation time that must pass without a new device
#: before the network counts as learned. Scales the quiet requirement so a
#: sensor up for ten hours needs a longer silence than one up for ten minutes.
SATURATION_RATIO = 0.2


def required_quiet(elapsed: timedelta, quiet_period: timedelta) -> timedelta:
    """Quiet time needed before the window may close."""
    return max(quiet_period, elapsed * SATURATION_RATIO)


def should_close_window(
    *,
    now: datetime,
    first_capture_at: datetime,
    last_discovery_at: datetime,
    quiet_period: timedelta,
    max_window: timedelta,
    floor: timedelta,
) -> bool:
    """True when the sensor has seen enough to call the network learned.

    ``max_window`` is checked before ``floor`` so a pathological config (cap
    shorter than floor) still terminates instead of holding the window open
    forever.
    """
    elapsed = now - first_capture_at
    if elapsed >= max_window:
        return True
    if elapsed < floor:
        return False
    return (now - last_discovery_at) >= required_quiet(elapsed, quiet_period)
