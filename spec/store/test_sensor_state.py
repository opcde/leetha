"""sensor_state — single-row learning-window tracking.

The automatic baseline needs to know when this sensor started watching the
network and whether it is still learning. That lives in one row, seeded at
initialize() and advanced as devices are discovered.
"""

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


@pytest.mark.asyncio
async def test_fresh_db_seeds_an_open_window(db):
    state = await db.get_sensor_state()
    assert state["first_capture_at"] is not None
    assert state["last_discovery_at"] is not None
    assert state["window_closed_at"] is None  # still learning
    assert _dt(state["first_capture_at"]) <= _now()


@pytest.mark.asyncio
async def test_get_sensor_state_is_idempotent(db):
    first = await db.get_sensor_state()
    second = await db.get_sensor_state()
    assert first == second


@pytest.mark.asyncio
async def test_only_one_row_can_exist(db):
    await db.get_sensor_state()
    cursor = await db.db.execute("SELECT COUNT(*) FROM sensor_state")
    assert (await cursor.fetchone())[0] == 1


@pytest.mark.asyncio
async def test_mark_discovery_advances_last_discovery_at(db):
    before = _dt((await db.get_sensor_state())["last_discovery_at"])
    stamp = before + timedelta(minutes=5)
    await db.mark_discovery(at=stamp)
    after = _dt((await db.get_sensor_state())["last_discovery_at"])
    assert after == stamp
    assert after > before


@pytest.mark.asyncio
async def test_mark_discovery_does_not_move_first_capture_at(db):
    original = (await db.get_sensor_state())["first_capture_at"]
    await db.mark_discovery(at=_now() + timedelta(hours=3))
    assert (await db.get_sensor_state())["first_capture_at"] == original


@pytest.mark.asyncio
async def test_close_and_reopen_window(db):
    stamp = _now()
    await db.close_learning_window(at=stamp)
    assert (await db.get_sensor_state())["window_closed_at"] is not None

    await db.reopen_learning_window()
    assert (await db.get_sensor_state())["window_closed_at"] is None


@pytest.mark.asyncio
async def test_close_is_idempotent_and_keeps_the_first_close_time(db):
    """Re-closing an already-closed window must not move the boundary.

    Devices are graded against this timestamp, so moving it would re-grade
    history.
    """
    first = _now()
    await db.close_learning_window(at=first)
    recorded = (await db.get_sensor_state())["window_closed_at"]

    await db.close_learning_window(at=first + timedelta(hours=1))
    assert (await db.get_sensor_state())["window_closed_at"] == recorded


@pytest.mark.asyncio
async def test_reopen_then_close_records_the_new_time(db):
    """After an explicit reopen, closing again is a genuinely new boundary."""
    first = _now()
    await db.close_learning_window(at=first)
    await db.reopen_learning_window()

    second = first + timedelta(hours=2)
    await db.close_learning_window(at=second)
    assert _dt((await db.get_sensor_state())["window_closed_at"]) == second


@pytest.mark.asyncio
async def test_heartbeat_updates_last_heartbeat_at(db):
    stamp = _now() + timedelta(minutes=1)
    await db.record_heartbeat(at=stamp)
    assert _dt((await db.get_sensor_state())["last_heartbeat_at"]) == stamp


@pytest.mark.asyncio
async def test_upgraded_db_backfills_from_existing_devices(db):
    """An existing install must not look like a brand-new sensor.

    Seeding first_capture_at to now() on upgrade would restart the learning
    window and silence genuinely new arrivals for a full window. Derive it
    from observation history instead.
    """
    oldest = _now() - timedelta(days=30)
    newest = _now() - timedelta(days=2)
    for i, seen in enumerate((oldest, newest, _now() - timedelta(days=10))):
        await db.upsert_device(Device(
            mac=f"aa:bb:cc:11:00:{i:02x}", first_seen=seen, last_seen=_now(),
        ))

    # Simulate a pre-upgrade DB: devices exist, sensor_state does not.
    await db.db.execute("DELETE FROM sensor_state")
    await db.db.commit()

    state = await db.get_sensor_state()
    assert _dt(state["first_capture_at"]) == oldest
    assert _dt(state["last_discovery_at"]) == newest


@pytest.mark.asyncio
async def test_seed_on_empty_db_uses_now_not_epoch(db):
    """No devices means no history to derive from; fall back to now()."""
    await db.db.execute("DELETE FROM sensor_state")
    await db.db.execute("DELETE FROM devices")
    await db.db.commit()

    state = await db.get_sensor_state()
    age = _now() - _dt(state["first_capture_at"])
    assert age < timedelta(minutes=1)
