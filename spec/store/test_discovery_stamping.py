"""Devices are stamped with the live window state as they are written.

Every device write funnels through Database.upsert_device*, so that is where
the sensor's current learning state gets recorded -- rather than at the several
places in app.py that construct a Device.
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


def _now():
    return datetime.now(timezone.utc)


def _dev(mac):
    return Device(mac=mac, first_seen=_now(), last_seen=_now())


@pytest.mark.asyncio
async def test_new_device_while_learning_is_stamped_learning(db):
    await db.upsert_device(_dev("aa:00:00:00:10:01"))
    assert (await db.get_device("aa:00:00:00:10:01")).discovery_context == "learning"


@pytest.mark.asyncio
async def test_new_device_after_window_closes_is_stamped_monitored(db):
    await db.close_learning_window()
    await db.upsert_device(_dev("aa:00:00:00:10:02"))
    assert (await db.get_device("aa:00:00:00:10:02")).discovery_context == "monitored"


@pytest.mark.asyncio
async def test_existing_device_keeps_its_original_stamp(db):
    """A device seen before the window closed stays 'learning' forever."""
    mac = "aa:00:00:00:10:03"
    await db.upsert_device(_dev(mac))
    await db.close_learning_window()
    await db.upsert_device(_dev(mac))  # seen again after closing
    assert (await db.get_device(mac)).discovery_context == "learning"


@pytest.mark.asyncio
async def test_new_device_advances_last_discovery_at(db):
    before = (await db.get_sensor_state())["last_discovery_at"]
    await db.upsert_device(_dev("aa:00:00:00:10:04"))
    after = (await db.get_sensor_state())["last_discovery_at"]
    assert after >= before


@pytest.mark.asyncio
async def test_repeat_sighting_does_not_advance_last_discovery_at(db):
    """Saturation must measure *new* devices, not traffic volume.

    If every packet from a known device counted as a discovery, the network
    would never look quiet and the window would never close.
    """
    mac = "aa:00:00:00:10:05"
    await db.upsert_device(_dev(mac))
    marker = (await db.get_sensor_state())["last_discovery_at"]

    for _ in range(5):
        await db.upsert_device(_dev(mac))

    assert (await db.get_sensor_state())["last_discovery_at"] == marker


@pytest.mark.asyncio
async def test_known_macs_survive_reopen(db):
    """Reopening the window must not make known devices look new again."""
    mac = "aa:00:00:00:10:06"
    await db.upsert_device(_dev(mac))
    await db.close_learning_window()
    await db.reopen_learning_window()
    await db.upsert_device(_dev(mac))
    assert (await db.get_device(mac)).discovery_context == "learning"


@pytest.mark.asyncio
async def test_stamping_works_on_an_existing_database(tmp_path):
    """A device already in the table is not re-stamped after a restart."""
    path = tmp_path / "restart.db"
    d = Database(path)
    await d.initialize()
    await d.upsert_device(_dev("aa:00:00:00:10:07"))
    await d.close_learning_window()
    await d.close()

    d2 = Database(path)
    await d2.initialize()
    try:
        # Fresh process: known-MAC cache must be rebuilt from the table, or the
        # device would be treated as a new arrival and re-stamped 'monitored'.
        await d2.upsert_device(_dev("aa:00:00:00:10:07"))
        assert (await d2.get_device("aa:00:00:00:10:07")).discovery_context == "learning"
    finally:
        await d2.close()
