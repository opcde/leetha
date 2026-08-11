"""Saturation math for the learning window.

The window closes when leetha stops discovering devices, not on a clock.
Sessions range from a one-hour assessment run to a multi-week deployment, so a
fixed duration either never closes for short runs or misfits long ones.
Saturation scales to network size instead of session length.
"""

from datetime import datetime, timedelta, timezone

from leetha.baseline import required_quiet, should_close_window

BASE = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
QUIET = timedelta(minutes=30)
CAP = timedelta(days=7)
FLOOR = timedelta(minutes=15)


def _call(elapsed, since_discovery):
    return should_close_window(
        now=BASE + elapsed,
        first_capture_at=BASE,
        last_discovery_at=BASE + elapsed - since_discovery,
        quiet_period=QUIET,
        max_window=CAP,
        floor=FLOOR,
    )


def test_stays_open_before_the_floor():
    """A momentarily idle interface must not close the window immediately."""
    assert _call(timedelta(minutes=10), timedelta(minutes=10)) is False


def test_stays_open_while_discovery_is_recent():
    assert _call(timedelta(hours=2), timedelta(minutes=5)) is False


def test_closes_after_quiet_period_on_a_young_sensor():
    # 2h elapsed -> required quiet = max(30m, 24m) = 30m
    assert _call(timedelta(hours=2), timedelta(minutes=31)) is True


def test_quiet_requirement_scales_with_elapsed_time():
    # 10h elapsed -> required quiet = max(30m, 2h) = 2h
    assert _call(timedelta(hours=10), timedelta(minutes=45)) is False
    assert _call(timedelta(hours=10), timedelta(hours=2, minutes=1)) is True


def test_closes_at_the_hard_cap_even_under_constant_churn():
    """A network that never stops churning must still leave learning."""
    assert _call(timedelta(days=8), timedelta(seconds=1)) is True


def test_short_assessment_run_reaches_maturity():
    """An 8-hour workday run must be able to close.

    This is the case a fixed 7-day window broke: the sensor would never mature,
    so new_host would stay INFO forever and the grading ladder never activates.
    """
    # 3h elapsed -> required quiet = max(30m, 36m) = 36m
    assert _call(timedelta(hours=3), timedelta(minutes=40)) is True


def test_floor_beats_a_dead_interface():
    """Zero discoveries plus zero elapsed time must not close instantly."""
    assert _call(timedelta(seconds=0), timedelta(seconds=0)) is False


def test_required_quiet_never_drops_below_the_configured_minimum():
    assert required_quiet(timedelta(minutes=1), QUIET) == QUIET
    assert required_quiet(timedelta(hours=100), QUIET) == timedelta(hours=20)


def test_cap_wins_over_floor_for_a_pathological_config():
    """max_window below floor must still terminate rather than deadlock."""
    assert should_close_window(
        now=BASE + timedelta(hours=1),
        first_capture_at=BASE,
        last_discovery_at=BASE,
        quiet_period=QUIET,
        max_window=timedelta(minutes=5),
        floor=timedelta(days=1),
    ) is True
