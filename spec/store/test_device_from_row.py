"""Device.from_row() must agree with _marshal_device().

There are two device marshallers. _marshal_device() reads by column name;
from_row() falls back to positional indices. A field added to one and not the
other silently returns its default, which for discovery_context means every
device reads back as 'learning' regardless of what is stored -- and new_host
would grade every genuine new arrival as INFO.
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


# NOTE: from_row()'s positional indices do not follow `SELECT *` order --
# migration-added columns (identity_id, manual_override) sit at the physical end
# of the table, so positional access only works for the canonical SELECT the
# fallback was written against. Named access is the contract worth pinning.


@pytest.mark.asyncio
async def test_from_row_matches_marshal_device(db):
    """Both marshallers must produce the same discovery_context."""
    await db.upsert_device(Device(
        mac="aa:bb:cc:22:00:02", first_seen=_now(), last_seen=_now(),
        discovery_context="monitored",
    ))
    via_marshal = await db.get_device("aa:bb:cc:22:00:02")

    async with db.db.execute(
        "SELECT * FROM devices WHERE mac = ?", ("aa:bb:cc:22:00:02",)
    ) as cur:
        row = await cur.fetchone()
    via_from_row = Device.from_row(row)

    assert via_from_row.discovery_context == via_marshal.discovery_context == "monitored"


def test_from_row_defaults_to_learning_when_column_absent():
    """Rows predating the migration must still marshal, defaulting to learning."""
    dev = Device.from_row({"mac": "aa:bb:cc:22:00:03"})
    assert dev.discovery_context == "learning"
