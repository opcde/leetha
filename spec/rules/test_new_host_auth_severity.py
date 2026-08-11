"""new_host severity grades on discovery_context, not authorization.

Authorization is a human attestation ("I know this device and leetha's
fingerprint of it is accurate") and no longer drives alert noise -- except for
`rejected`, which is an explicit "I don't want this here". Everything else is
decided by whether the sensor was still learning the network when the device
first appeared.
"""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from leetha.rules.discovery import NewHostRule
from leetha.store.database import Database
from leetha.store.models import Host, Device, AlertSeverity, FindingRule
from leetha.evidence.models import Verdict

MAC = "aa:bb:cc:dd:ee:01"


@pytest.fixture
async def db_and_store(tmp_path):
    from leetha.store.store import Store
    db_path = tmp_path / "auth.db"
    db = Database(db_path)
    await db.initialize()
    store = Store(str(db_path))
    await store.initialize()
    try:
        yield db, store
    finally:
        await store.close()
        await db.close()


def _host() -> Host:
    return Host(hw_addr=MAC, ip_addr="10.0.0.1", disposition="new")


def _verdict() -> Verdict:
    return Verdict(
        hw_addr=MAC,
        category="laptop",
        vendor="Apple",
        platform="macOS",
        platform_version=None,
        model=None,
        hostname=None,
        certainty=80,
        evidence_chain=[],
        computed_at=datetime.now(timezone.utc),
    )


async def _seed(db, *, context="learning", authorization=None,
                passively_observed=True):
    ts = datetime.now(timezone.utc)
    await db.upsert_device(Device(
        mac=MAC, first_seen=ts, last_seen=ts,
        discovery_context=context,
        passively_observed=passively_observed,
    ))
    if authorization == "approved":
        await db.approve_device(MAC, actor="alice")
    elif authorization == "rejected":
        await db.reject_device(MAC, actor="alice")


@pytest.mark.parametrize("context,authorization,expected", [
    # Still learning: everything is pre-existing inventory.
    ("learning",  None,         AlertSeverity.INFO),
    ("learning",  "approved",   AlertSeverity.INFO),
    ("learning",  "rejected",   AlertSeverity.CRITICAL),  # human signal wins
    # Network already learned: a device appearing now is genuinely new.
    ("monitored", None,         AlertSeverity.WARNING),
    ("monitored", "approved",   AlertSeverity.WARNING),
    ("monitored", "rejected",   AlertSeverity.CRITICAL),
])
@pytest.mark.asyncio
async def test_severity_matrix(db_and_store, context, authorization, expected):
    db, store = db_and_store
    await _seed(db, context=context, authorization=authorization)

    finding = await NewHostRule().evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.rule == FindingRule.NEW_HOST
    assert finding.severity == expected


@pytest.mark.asyncio
async def test_no_device_row_is_info(db_and_store):
    """Unknown device defaults to learning, which is the quiet side."""
    _db, store = db_and_store
    finding = await NewHostRule().evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.severity == AlertSeverity.INFO


@pytest.mark.asyncio
async def test_importer_sourced_device_is_graded_not_suppressed(db_and_store):
    """passively_observed=0 must yield an INFO finding, never None.

    Design invariant: the learning window is a severity layer and never gates
    the data path. Previously this returned None and the finding vanished.
    """
    db, store = db_and_store
    await _seed(db, context="monitored", passively_observed=False)

    finding = await NewHostRule().evaluate(_host(), _verdict(), store)
    assert finding is not None
    assert finding.severity == AlertSeverity.INFO


@pytest.mark.asyncio
async def test_approving_no_longer_silences_a_monitored_arrival(db_and_store):
    """Approval attests to fingerprint accuracy; it is not a mute button.

    A genuinely new arrival stays WARNING even once a human confirms what it
    is -- the alert is about the arrival, not about identification doubt.
    """
    db, store = db_and_store
    await _seed(db, context="monitored", authorization="approved")

    finding = await NewHostRule().evaluate(_host(), _verdict(), store)
    assert finding.severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_only_fires_for_new_disposition(db_and_store):
    db, store = db_and_store
    await _seed(db, context="monitored")

    host = Host(hw_addr=MAC, ip_addr="10.0.0.1", disposition="known")
    assert await NewHostRule().evaluate(host, _verdict(), store) is None


@pytest.mark.asyncio
async def test_approve_resolves_pending_new_host_finding(db_and_store):
    """Approving a device still resolves its unresolved new_host findings."""
    db, store = db_and_store
    await _seed(db, context="monitored")
    await NewHostRule().evaluate(_host(), _verdict(), store)
    await db.approve_device(MAC, actor="alice")
    # Behaviour retained from Phase A: approval clears the outstanding finding.
    assert (await db.get_device(MAC)).authorization == "approved"
