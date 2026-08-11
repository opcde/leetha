"""Proxmox VE inventory importer.

Passive capture sees a VM's MAC and can tell it is virtualised, but not which
guest it is or which hypervisor runs it. The Proxmox API closes that gap: the
per-guest config carries the NIC MAC addresses, so captured traffic can be
attributed to a named VM or container on a named node.

Needs only a read-only API token (``PVEAuditor`` role).
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator

from leetha.inventory.base import BaseImporter, ImportedDevice, TestResult
from leetha.inventory.config_schema import ConfigField
from leetha.inventory.registry import register_importer

log = logging.getLogger(__name__)

# net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=20
_NET_MAC_RE = re.compile(
    r"(?:^|,)(?:virtio|e1000|rtl8139|vmxnet3|hwaddr)=([0-9A-Fa-f:]{17})",
)
_NET_KEY_RE = re.compile(r"^net\d+$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)


def extract_macs(guest_config: dict) -> list[str]:
    """Pull NIC MAC addresses out of a Proxmox guest config payload.

    QEMU guests use ``net0: virtio=<mac>,...`` while LXC containers use
    ``net0: name=eth0,hwaddr=<mac>,...`` -- both are covered.
    """
    macs: list[str] = []
    for key, value in (guest_config or {}).items():
        if not _NET_KEY_RE.match(str(key)) or not isinstance(value, str):
            continue
        for found in _NET_MAC_RE.findall(value):
            mac = found.lower()
            if _MAC_RE.match(mac) and mac not in macs:
                macs.append(mac)
    return macs


@register_importer("proxmox")
class ProxmoxImporter(BaseImporter):
    """Imports Proxmox VE nodes, QEMU VMs, and LXC containers."""

    def __init__(self) -> None:
        self._config: dict = {}

    def configure(self, config: dict) -> None:
        self._config = config or {}

    @classmethod
    def config_schema(cls) -> list[ConfigField]:
        return [
            ConfigField(name="host", type="string", required=True,
                        help="Proxmox host or IP (e.g. pve.lan or 10.0.0.2)"),
            ConfigField(name="port", type="int", default=8006,
                        help="API port (default 8006)"),
            ConfigField(name="token_id", type="string", required=True,
                        help="API token ID, e.g. leetha@pve!inventory"),
            ConfigField(name="token_secret", type="secret", required=True,
                        help="API token secret (PVEAuditor role is enough)"),
            ConfigField(name="verify_tls", type="bool", default=False,
                        help="Verify the TLS certificate (Proxmox ships a self-signed cert)"),
            ConfigField(name="include_stopped", type="bool", default=True,
                        help="Import guests that are not currently running"),
        ]

    # -- HTTP helpers ----------------------------------------------------

    def _base_url(self) -> str:
        host = str(self._config.get("host", "")).strip()
        port = self._config.get("port") or 8006
        return f"https://{host}:{port}/api2/json"

    def _headers(self) -> dict:
        return {
            "Authorization": (
                f"PVEAPIToken={self._config.get('token_id', '')}="
                f"{self._config.get('token_secret', '')}"
            )
        }

    async def _get(self, session, path: str):
        """GET one API path, returning the unwrapped ``data`` payload."""
        import aiohttp

        url = f"{self._base_url()}{path}"
        timeout = aiohttp.ClientTimeout(total=30)
        async with session.get(url, headers=self._headers(), timeout=timeout) as resp:
            resp.raise_for_status()
            body = await resp.json()
        return body.get("data")

    def _session(self):
        import aiohttp

        verify = bool(self._config.get("verify_tls", False))
        connector = aiohttp.TCPConnector(ssl=None if verify else False)
        return aiohttp.ClientSession(connector=connector)

    # -- BaseImporter ----------------------------------------------------

    async def test_connection(self) -> TestResult:
        for field in ("host", "token_id", "token_secret"):
            if not self._config.get(field):
                return TestResult(ok=False, message=f"missing config: {field}")
        try:
            async with self._session() as session:
                nodes = await self._get(session, "/nodes") or []
        except Exception as err:
            return TestResult(ok=False, message=f"connection failed: {err}")

        names = ", ".join(str(n.get("node")) for n in nodes if n.get("node"))
        return TestResult(
            ok=True,
            message=f"connected — {len(nodes)} node(s): {names}" if names
                    else "connected — no nodes visible to this token",
            device_count=len(nodes),
        )

    async def sync(self) -> AsyncIterator[ImportedDevice]:
        if not self._config.get("host") or not self._config.get("token_id"):
            log.warning("proxmox importer is not configured")
            return

        include_stopped = bool(self._config.get("include_stopped", True))

        try:
            session_cm = self._session()
        except ImportError:  # pragma: no cover - aiohttp is a hard dependency
            log.error("aiohttp unavailable; proxmox import skipped")
            return

        async with session_cm as session:
            try:
                nodes = await self._get(session, "/nodes") or []
            except Exception as err:
                log.error("proxmox: listing nodes failed: %s", err)
                return

            for node in nodes:
                node_name = node.get("node")
                if not node_name:
                    continue

                for kind, endpoint in (("qemu", "qemu"), ("lxc", "lxc")):
                    try:
                        guests = await self._get(
                            session, f"/nodes/{node_name}/{endpoint}") or []
                    except Exception as err:
                        log.warning("proxmox: listing %s on %s failed: %s",
                                    kind, node_name, err)
                        continue

                    for guest in guests:
                        vmid = guest.get("vmid")
                        status = guest.get("status")
                        if vmid is None:
                            continue
                        if not include_stopped and status != "running":
                            continue

                        try:
                            conf = await self._get(
                                session,
                                f"/nodes/{node_name}/{endpoint}/{vmid}/config",
                            ) or {}
                        except Exception as err:
                            log.warning("proxmox: config for %s/%s failed: %s",
                                        node_name, vmid, err)
                            continue

                        macs = extract_macs(conf)
                        if not macs:
                            # Nothing to correlate captured traffic against.
                            continue

                        name = guest.get("name") or conf.get("hostname") or f"{kind}-{vmid}"
                        for mac in macs:
                            yield ImportedDevice(
                                mac=mac,
                                ip=None,  # guest IPs need the agent; MAC is enough to correlate
                                hostname=name,
                                source="proxmox",
                                certainty=0.90,
                                metadata={
                                    "proxmox_node": node_name,
                                    "vmid": vmid,
                                    "guest_type": "vm" if kind == "qemu" else "container",
                                    "status": status,
                                    "cores": conf.get("cores"),
                                    "memory_mb": conf.get("memory"),
                                },
                            )
