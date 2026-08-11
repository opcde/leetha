"""devices.discovery_context — stamped once at discovery, never overwritten.

The learning window grades new_host severity off this column. It must be
immutable after first write so that later upserts, config changes, or window
transitions cannot retroactively re-grade a device.
"""

import pytest
from datetime import datetime, timezone
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


@pytest.fixture
async def file_db(tmp_path):
    """A file-backed Database, always closed.

    aiosqlite owns a non-daemon worker thread, so a test that fails before
    close() leaves it running and pytest hangs at exit. Cleanup belongs in a
    fixture finalizer, not the test body.
    """
    d = Database(tmp_path / "upgrade.db")
    await d.initialize()
    try:
        yield d
    finally:
        await d.close()


def _now():
    return datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_default_context_is_learning(db):
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:01", first_seen=_now(), last_seen=_now(),
    ))
    dev = await db.get_device("aa:bb:cc:00:00:01")
    assert dev.discovery_context == "learning"


@pytest.mark.asyncio
async def test_monitored_context_persists(db):
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:02", first_seen=_now(), last_seen=_now(),
        discovery_context="monitored",
    ))
    dev = await db.get_device("aa:bb:cc:00:00:02")
    assert dev.discovery_context == "monitored"


@pytest.mark.asyncio
async def test_context_is_not_overwritten_by_later_upserts(db):
    """First write wins: a device stamped 'monitored' stays monitored."""
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:03", first_seen=_now(), last_seen=_now(),
        discovery_context="monitored",
    ))
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:03", first_seen=_now(), last_seen=_now(),
        discovery_context="learning",
    ))
    dev = await db.get_device("aa:bb:cc:00:00:03")
    assert dev.discovery_context == "monitored"


@pytest.mark.asyncio
async def test_learning_context_is_not_overwritten_either(db):
    """The guard is symmetric — a 'learning' stamp is equally immutable."""
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:04", first_seen=_now(), last_seen=_now(),
        discovery_context="learning",
    ))
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:04", first_seen=_now(), last_seen=_now(),
        discovery_context="monitored",
    ))
    dev = await db.get_device("aa:bb:cc:00:00:04")
    assert dev.discovery_context == "learning"


@pytest.mark.asyncio
async def test_upsert_preserves_other_columns(db):
    """Regression guard: the added bind parameter must not shift the others."""
    await db.upsert_device(Device(
        mac="aa:bb:cc:00:00:05", first_seen=_now(), last_seen=_now(),
        hostname="printer", manufacturer="Brother", device_type="Printer",
        confidence=77, notes="hallway", presence_threshold_seconds=600,
    ))
    dev = await db.get_device("aa:bb:cc:00:00:05")
    assert dev.hostname == "printer"
    assert dev.manufacturer == "Brother"
    assert dev.device_type == "Printer"
    assert dev.confidence == 77
    assert dev.notes == "hallway"
    assert dev.presence_threshold_seconds == 600
    assert dev.discovery_context == "learning"


@pytest.mark.asyncio
async def test_migration_backfills_existing_devices_to_learning(file_db):
    """An upgraded DB backfills to 'learning'.

    Everything known at upgrade time is pre-existing inventory, so it must not
    grade as a new arrival.
    """
    # Simulate a pre-upgrade schema by removing the column, then re-running
    # migrations the way an upgrade would. The index goes first: SQLite will
    # not drop a column an index still references. (A real upgrade never drops
    # anything -- migrations add the column before the index is created.)
    await file_db.db.execute("DROP INDEX IF EXISTS idx_devices_discovery_context")
    await file_db.db.execute("ALTER TABLE devices DROP COLUMN discovery_context")
    await file_db.db.execute(
        "INSERT INTO devices (mac, first_seen, last_seen) VALUES (?, ?, ?)",
        ("aa:bb:cc:00:00:06", _now().isoformat(), _now().isoformat()),
    )
    await file_db.db.commit()

    await file_db._apply_migrations()
    await file_db.db.commit()

    dev = await file_db.get_device("aa:bb:cc:00:00:06")
    assert dev.discovery_context == "learning"
