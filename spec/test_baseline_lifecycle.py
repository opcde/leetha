"""Learning-window lifecycle: closing, burst re-entry, outage recovery."""

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from leetha.baseline import BURST_THRESHOLD, BURST_WINDOW, evaluate_window
from leetha.config import LeethaConfig
from leetha.store.database import Database
from leetha.store.models import Device


@pytest.fixture
async def db():
    d = Database(Path(":memory:"))
    await d.initialize()
    try:
        yield d
    finally:
        await d.close()


def _now():
    return datetime.now(timezone.utc)


def _cfg(**kw):
    c = LeethaConfig()
    for k, v in kw.items():
        setattr(c, k, v)
    return c


async def _age_sensor(db, hours):
    """Backdate first_capture_at so the sensor looks older than it is."""
    stamp = (_now() - timedelta(hours=hours)).isoformat()
    await db.db.execute(
        "UPDATE sensor_state SET first_capture_at = ? WHERE id = 1", (stamp,)
    )
    await db.db.commit()


async def _quiet_for(db, minutes):
    stamp = (_now() - timedelta(minutes=minutes)).isoformat()
    await db.db.execute(
        "UPDATE sensor_state SET last_discovery_at = ? WHERE id = 1", (stamp,)
    )
    await db.db.commit()


# --- closing ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_window_closes_once_discovery_saturates(db):
    await _age_sensor(db, 3)
    await _quiet_for(db, 45)
    await evaluate_window(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is not None


@pytest.mark.asyncio
async def test_window_stays_open_while_devices_keep_arriving(db):
    await _age_sensor(db, 3)
    await _quiet_for(db, 2)
    await evaluate_window(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is None


@pytest.mark.asyncio
async def test_always_learning_never_closes(db):
    """The assessment-run mode: never escalate, whatever the traffic does."""
    await _age_sensor(db, 100)
    await _quiet_for(db, 5000)
    await evaluate_window(db, _cfg(baseline_learning_mode="always_learning"))
    assert (await db.get_sensor_state())["window_closed_at"] is None


@pytest.mark.asyncio
async def test_manual_mode_never_closes_on_its_own(db):
    await _age_sensor(db, 100)
    await _quiet_for(db, 5000)
    await evaluate_window(db, _cfg(baseline_learning_mode="manual"))
    assert (await db.get_sensor_state())["window_closed_at"] is None


@pytest.mark.asyncio
async def test_closed_window_is_not_reclosed(db):
    await db.close_learning_window()
    first = (await db.get_sensor_state())["window_closed_at"]
    await _age_sensor(db, 200)
    await evaluate_window(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] == first


# --- burst re-entry --------------------------------------------------------

@pytest.mark.asyncio
async def test_burst_of_new_macs_reopens_the_window(db):
    """The morning flood: many unseen MACs at once means the net woke up."""
    await db.close_learning_window()
    for i in range(BURST_THRESHOLD):
        await db.upsert_device(Device(
            mac=f"bb:00:00:00:00:{i:02x}", first_seen=_now(), last_seen=_now(),
        ))
    await evaluate_window(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is None


@pytest.mark.asyncio
async def test_burst_flips_those_devices_back_to_learning(db):
    await db.close_learning_window()
    macs = [f"bb:00:00:00:01:{i:02x}" for i in range(BURST_THRESHOLD)]
    for m in macs:
        await db.upsert_device(Device(mac=m, first_seen=_now(), last_seen=_now()))
    await evaluate_window(db, _cfg())
    for m in macs:
        assert (await db.get_device(m)).discovery_context == "learning"


@pytest.mark.asyncio
async def test_a_single_new_device_is_not_a_burst(db):
    """One genuinely new device must stay a WARNING-worthy arrival."""
    await db.close_learning_window()
    await db.upsert_device(Device(
        mac="bb:00:00:00:02:01", first_seen=_now(), last_seen=_now(),
    ))
    await evaluate_window(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is not None
    assert (await db.get_device("bb:00:00:00:02:01")).discovery_context == "monitored"


@pytest.mark.asyncio
async def test_burst_deletes_no_data(db):
    """Invariant: the window is a severity layer, never a data-path gate."""
    await db.close_learning_window()
    for i in range(BURST_THRESHOLD):
        await db.upsert_device(Device(
            mac=f"bb:00:00:00:03:{i:02x}", first_seen=_now(), last_seen=_now(),
        ))
    async with db.db.execute("SELECT COUNT(*) FROM devices") as c:
        before = (await c.fetchone())[0]

    await evaluate_window(db, _cfg())

    async with db.db.execute("SELECT COUNT(*) FROM devices") as c:
        assert (await c.fetchone())[0] == before


@pytest.mark.asyncio
async def test_old_arrivals_outside_the_burst_window_do_not_trigger(db):
    """Devices spread over hours are normal growth, not a wake-up burst."""
    await db.close_learning_window()
    old = _now() - BURST_WINDOW - timedelta(minutes=10)
    for i in range(BURST_THRESHOLD):
        await db.upsert_device(Device(
            mac=f"bb:00:00:00:04:{i:02x}", first_seen=old, last_seen=old,
        ))
    await evaluate_window(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is not None


# --- outage ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_long_outage_reopens_learning(db):
    """Leetha was not watching, so it cannot claim what it sees now is new."""
    await db.close_learning_window()
    stale = (_now() - timedelta(days=30)).isoformat()
    await db.db.execute(
        "UPDATE sensor_state SET last_heartbeat_at = ? WHERE id = 1", (stale,)
    )
    await db.db.commit()

    from leetha.baseline import recover_from_outage
    await recover_from_outage(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is None


@pytest.mark.asyncio
async def test_brief_restart_does_not_reopen(db):
    await db.close_learning_window()
    recent = (_now() - timedelta(seconds=30)).isoformat()
    await db.db.execute(
        "UPDATE sensor_state SET last_heartbeat_at = ? WHERE id = 1", (recent,)
    )
    await db.db.commit()

    from leetha.baseline import recover_from_outage
    await recover_from_outage(db, _cfg())
    assert (await db.get_sensor_state())["window_closed_at"] is not None
