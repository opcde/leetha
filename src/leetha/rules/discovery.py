"""Discovery-related finding rules."""
from __future__ import annotations
import logging
from datetime import datetime, timedelta, timezone
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

_LOW_CERT_LAST_FIRED: dict[str, datetime] = {}
_LOW_CERT_COOLDOWN = timedelta(hours=1)

logger = logging.getLogger(__name__)


async def _device_authorization(store, mac: str) -> str:
    """Look up a device's authorization state. Default: 'unapproved'."""
    try:
        cursor = await store.connection.execute(
            "SELECT authorization FROM devices WHERE mac = ?", (mac,),
        )
        row = await cursor.fetchone()
    except Exception:
        return "unapproved"
    if row is None or row[0] is None:
        return "unapproved"
    return row[0]


async def _device_passively_observed(store, mac: str) -> bool:
    """True if the device has been observed in live capture (or row missing)."""
    try:
        cursor = await store.connection.execute(
            "SELECT passively_observed FROM devices WHERE mac = ?", (mac,),
        )
        row = await cursor.fetchone()
    except Exception:
        return True
    if row is None or row[0] is None:
        return True
    return bool(row[0])


async def _device_discovery_context(store, mac: str) -> str:
    """Return the sensor's learning state when this device was discovered.

    Defaults to 'learning' — the quiet side. Failing quiet on a DB fault is
    deliberate: failing loud would turn any transient error into an alert
    flood, which trains operators to ignore the channel. The fault itself is
    surfaced through the log.
    """
    try:
        cursor = await store.connection.execute(
            "SELECT discovery_context FROM devices WHERE mac = ?", (mac,),
        )
        row = await cursor.fetchone()
    except Exception as exc:
        logger.warning(
            "discovery_context lookup failed for %s (%s); grading INFO", mac, exc
        )
        return "learning"
    if row is None or row[0] is None:
        return "learning"
    return row[0]


@register_rule("new_host")
class NewHostRule(RuleBase):
    severity = "info"  # graded dynamically; retained for registry-level defaults

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        # Only fire on truly new hosts (disposition still "new").
        # The pipeline transitions disposition to "known" after rules run,
        # so this will only fire once per host.
        if host.disposition == "new":
            auth = await _device_authorization(store, host.hw_addr)
            context = await _device_discovery_context(store, host.hw_addr)

            # Severity is decided by whether the sensor had learned the network
            # when this device appeared. Authorization no longer grades noise --
            # it records that a human vouched for the device's identity -- with
            # the single exception of 'rejected', an explicit "not welcome here".
            if auth == "rejected":
                sev = AlertSeverity.CRITICAL
            elif context == "learning":
                sev = AlertSeverity.INFO
            else:
                sev = AlertSeverity.WARNING

            # Importer-sourced devices not yet seen in live capture are graded
            # down rather than suppressed: the window is a severity layer and
            # never gates the data path, so the finding is still recorded.
            if not await _device_passively_observed(store, host.hw_addr):
                sev = AlertSeverity.INFO

            parts = [f"New host discovered: {host.hw_addr}"]
            if verdict.vendor:
                parts.append(verdict.vendor)
            if verdict.category:
                parts.append(verdict.category)
            if host.ip_addr:
                parts.append(host.ip_addr)
            if host.mac_randomized:
                parts.append("randomized MAC")
            if auth == "rejected":
                parts.append("authorization: rejected")
            return Finding(
                hw_addr=host.hw_addr,
                rule=FindingRule.NEW_HOST,
                severity=sev,
                message=" — ".join(parts),
            )
        return None

@register_rule("low_certainty")
class LowCertaintyRule(RuleBase):
    severity = "low"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if verdict.certainty < 50 and host.disposition in ("known", "new"):
            hw_addr = host.hw_addr
            # In-memory cooldown: don't fire more than once per hour
            last = _LOW_CERT_LAST_FIRED.get(hw_addr)
            if last and (datetime.now(timezone.utc) - last) < _LOW_CERT_COOLDOWN:
                return None
            # DB dedup: skip if an unresolved finding already exists
            cursor = await store.connection.execute(
                "SELECT COUNT(*) FROM findings WHERE hw_addr = ? AND rule = ? AND resolved = 0",
                (hw_addr, "low_certainty"),
            )
            if (await cursor.fetchone())[0] > 0:
                return None
            _LOW_CERT_LAST_FIRED[hw_addr] = datetime.now(timezone.utc)
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.LOW_CERTAINTY,
                severity=AlertSeverity.LOW,
                message=f"Host {hw_addr} has low identification certainty ({verdict.certainty}%)",
            )
        return None
