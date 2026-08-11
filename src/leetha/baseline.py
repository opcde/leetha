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

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

#: Fraction of total observation time that must pass without a new device
#: before the network counts as learned. Scales the quiet requirement so a
#: sensor up for ten hours needs a longer silence than one up for ten minutes.
SATURATION_RATIO = 0.2

#: Minimum observation time before the window may close at all, so a briefly
#: idle interface at startup cannot end learning immediately.
LEARNING_FLOOR = timedelta(minutes=15)

#: A cluster of this many never-before-seen MACs inside BURST_WINDOW is read as
#: "the network woke up" rather than as that many separate intrusions.
BURST_THRESHOLD = 3
BURST_WINDOW = timedelta(minutes=5)


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


def _parse(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None


async def _burst_macs(db, since: datetime) -> list[str]:
    """MACs stamped 'monitored' that first appeared inside the burst window."""
    async with db.db.execute(
        "SELECT mac FROM devices "
        "WHERE discovery_context = 'monitored' AND first_seen >= ?",
        (since.isoformat(),),
    ) as cur:
        return [r[0] for r in await cur.fetchall()]


async def evaluate_window(db, config) -> None:
    """Advance the learning window one tick.

    Closes it once discovery saturates, or re-enters learning when a burst of
    unseen MACs says the network merely woke up. Only ``automatic`` mode moves
    the window on its own -- ``always_learning`` never escalates, and
    ``manual`` waits for an explicit "finish learning now".
    """
    mode = getattr(config, "baseline_learning_mode", "automatic")
    state = await db.get_sensor_state()
    now = datetime.now(timezone.utc)

    if state["window_closed_at"] is not None:
        # Closed: the only automatic transition left is burst re-entry.
        macs = await _burst_macs(db, now - BURST_WINDOW)
        if len(macs) >= BURST_THRESHOLD:
            logger.info(
                "Discovery burst (%d new MACs in %s) — re-entering learning",
                len(macs), BURST_WINDOW,
            )
            await db.apply_burst_reentry(macs)
        return

    if mode != "automatic":
        return

    first_capture = _parse(state["first_capture_at"])
    last_discovery = _parse(state["last_discovery_at"])
    if first_capture is None or last_discovery is None:
        return

    if should_close_window(
        now=now,
        first_capture_at=first_capture,
        last_discovery_at=last_discovery,
        quiet_period=timedelta(
            minutes=getattr(config, "baseline_quiet_period_minutes", 30)),
        max_window=timedelta(
            days=getattr(config, "baseline_max_window_days", 7)),
        floor=LEARNING_FLOOR,
    ):
        logger.info("Network learned — new arrivals now grade as WARNING")
        await db.close_learning_window(at=now)


async def recover_from_outage(db, config) -> None:
    """Re-enter learning if the sensor was down longer than the window.

    Leetha cannot claim a device is new if it was not watching when the device
    arrived, so a long gap in the heartbeat has to reopen learning.
    """
    state = await db.get_sensor_state()
    if state["window_closed_at"] is None:
        return
    beat = _parse(state["last_heartbeat_at"])
    if beat is None:
        return

    gap = datetime.now(timezone.utc) - beat
    if gap >= timedelta(days=getattr(config, "baseline_max_window_days", 7)):
        logger.info(
            "Sensor was down for %s — re-entering learning rather than "
            "reporting everything that arrived meanwhile as new", gap,
        )
        await db.reopen_learning_window()
