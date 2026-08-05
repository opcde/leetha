"""Zigbee2MQTT and Z-Wave JS UI inventory importers.

Zigbee and Z-Wave devices never touch IP, so passive capture cannot see them
at all -- a Hue bulb or a door sensor is invisible no matter how long leetha
listens. Their controllers already publish a full device list over MQTT, so
importing it is the only way these devices enter the inventory.

Zigbee devices carry an EUI-64 whose top three octets are a real IEEE OUI,
so imported records still resolve a vendor through the normal OUI lookup.
Z-Wave has no equivalent, so those devices are keyed by home ID and node ID.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator

from leetha.inventory.base import BaseImporter, ImportedDevice, TestResult
from leetha.inventory.config_schema import ConfigField
from leetha.inventory.registry import register_importer

log = logging.getLogger(__name__)

_HEX_RE = re.compile(r"^[0-9a-f]+$")


def normalise_eui64(raw: str | None) -> str | None:
    """Normalise a Zigbee IEEE address to colon-separated lowercase octets.

    Accepts ``0x00124b0021f8ab12``, ``00124b0021f8ab12``, or an already
    colon-separated form. Returns None when the value is not a 64-bit address.
    """
    if not raw:
        return None
    text = str(raw).strip().lower().replace(":", "").replace("-", "")
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != 16 or not _HEX_RE.match(text):
        return None
    return ":".join(text[i:i + 2] for i in range(0, 16, 2))


def parse_zigbee2mqtt_devices(payload) -> list[ImportedDevice]:
    """Parse a ``zigbee2mqtt/bridge/devices`` payload into device records."""
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return []
    if not isinstance(payload, list):
        return []

    devices: list[ImportedDevice] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        # The coordinator is the radio itself, not a discovered device.
        if entry.get("type") == "Coordinator":
            continue
        addr = normalise_eui64(entry.get("ieee_address"))
        if addr is None:
            continue

        definition = entry.get("definition") or {}
        vendor = definition.get("vendor")
        model = definition.get("model")
        friendly = entry.get("friendly_name")

        devices.append(ImportedDevice(
            mac=addr,
            ip=None,
            hostname=friendly,
            source="zigbee2mqtt",
            # The controller is authoritative about its own paired devices.
            certainty=0.95,
            metadata={
                "protocol": "zigbee",
                "vendor": vendor,
                "model": model,
                "description": definition.get("description"),
                "device_role": entry.get("type"),          # Router / EndDevice
                "power_source": entry.get("power_source"),
                "network_address": entry.get("network_address"),
                "supported": entry.get("supported"),
            },
        ))
    return devices


def parse_zwave_nodes(payload, home_id: str | None = None) -> list[ImportedDevice]:
    """Parse a Z-Wave JS UI node dump into device records.

    Z-Wave node IDs are only unique within a controller, so the synthetic
    identifier embeds the home ID to stay stable and collision-free.
    """
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return []

    if isinstance(payload, dict):
        # ZUI publishes either {"nodes": [...]} or a nodeId-keyed mapping.
        nodes = payload.get("nodes")
        if nodes is None:
            nodes = [v for v in payload.values() if isinstance(v, dict)]
        payload = nodes
    if not isinstance(payload, list):
        return []

    devices: list[ImportedDevice] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        node_id = entry.get("id", entry.get("nodeId"))
        if node_id is None:
            continue
        if entry.get("isControllerNode"):
            continue

        hid = str(home_id or entry.get("homeId") or "zwave").lower()
        identifier = f"zwave:{hid}:{node_id}"

        name = entry.get("name") or entry.get("productLabel") or f"zwave-node-{node_id}"
        devices.append(ImportedDevice(
            mac=identifier,
            ip=None,
            hostname=name,
            source="zwave_js",
            certainty=0.95,
            metadata={
                "protocol": "zwave",
                "node_id": node_id,
                "home_id": hid,
                "vendor": entry.get("manufacturer"),
                "model": entry.get("productLabel") or entry.get("productDescription"),
                "device_role": (
                    "controller" if entry.get("isControllerNode")
                    else ("router" if entry.get("isRouting") else "end_device")
                ),
                "status": entry.get("status"),
                "location": entry.get("loc") or entry.get("location"),
            },
        ))
    return devices


class _MQTTImporterBase(BaseImporter):
    """Shared MQTT plumbing for the Zigbee and Z-Wave importers."""

    #: MQTT topic suffix appended to the configured base topic.
    topic_suffix = ""

    def __init__(self) -> None:
        self._config: dict = {}

    def configure(self, config: dict) -> None:
        self._config = config or {}

    @classmethod
    def _mqtt_fields(cls, default_topic: str) -> list[ConfigField]:
        return [
            ConfigField(name="broker", type="string", required=True,
                        help="MQTT broker host or IP"),
            ConfigField(name="port", type="int", default=1883,
                        help="MQTT broker port (default 1883)"),
            ConfigField(name="base_topic", type="string", default=default_topic,
                        help=f"Base topic (default {default_topic})"),
            ConfigField(name="username", type="string",
                        help="MQTT username, if the broker requires auth"),
            ConfigField(name="password", type="secret",
                        help="MQTT password, if the broker requires auth"),
            ConfigField(name="timeout", type="int", default=15,
                        help="Seconds to wait for the retained device list"),
        ]

    def _topic(self) -> str:
        base = str(self._config.get("base_topic", "")).strip().rstrip("/")
        return f"{base}/{self.topic_suffix}" if self.topic_suffix else base

    async def _fetch_retained(self) -> object | None:
        """Subscribe and return the first retained message on the topic.

        Both controllers publish their device list as a retained message, so a
        subscribe is enough -- no request/response round trip is needed.
        """
        try:
            import aiomqtt
        except Exception as err:
            # Not just ImportError: aiomqtt pulls in paho -> dnspython ->
            # service_identity -> pyOpenSSL, so a broken transitive
            # dependency surfaces as AttributeError at import time. An
            # importer must never take the caller down with it.
            log.error(
                "%s importer could not load 'aiomqtt' (%s: %s)",
                self.name, type(err).__name__, err,
            )
            return None

        import asyncio

        broker = self._config.get("broker")
        if not broker:
            return None

        timeout = int(self._config.get("timeout", 15) or 15)
        client = aiomqtt.Client(
            hostname=broker,
            port=int(self._config.get("port", 1883) or 1883),
            username=self._config.get("username") or None,
            password=self._config.get("password") or None,
        )

        async def _read() -> object | None:
            async with client:
                await client.subscribe(self._topic())
                async for message in client.messages:
                    return message.payload
            return None

        try:
            return await asyncio.wait_for(_read(), timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("%s: no retained message on %s within %ss",
                        self.name, self._topic(), timeout)
            return None
        except Exception as err:
            log.error("%s: MQTT read failed: %s", self.name, err)
            return None

    def _parse(self, payload) -> list[ImportedDevice]:  # pragma: no cover - overridden
        raise NotImplementedError

    async def test_connection(self) -> TestResult:
        if not self._config.get("broker"):
            return TestResult(ok=False, message="no broker configured")
        payload = await self._fetch_retained()
        if payload is None:
            return TestResult(
                ok=False,
                message=f"no retained message on {self._topic()}",
            )
        devices = self._parse(payload)
        return TestResult(
            ok=True,
            message=f"found {len(devices)} device(s) on {self._topic()}",
            device_count=len(devices),
        )

    async def sync(self) -> AsyncIterator[ImportedDevice]:
        payload = await self._fetch_retained()
        if payload is None:
            return
        for device in self._parse(payload):
            yield device


@register_importer("zigbee2mqtt")
class Zigbee2MQTTImporter(_MQTTImporterBase):
    """Imports paired Zigbee devices from Zigbee2MQTT's bridge topic."""

    topic_suffix = "bridge/devices"

    @classmethod
    def config_schema(cls) -> list[ConfigField]:
        return cls._mqtt_fields("zigbee2mqtt")

    def _parse(self, payload) -> list[ImportedDevice]:
        return parse_zigbee2mqtt_devices(payload)


@register_importer("zwave_js")
class ZWaveJSImporter(_MQTTImporterBase):
    """Imports Z-Wave nodes published by Z-Wave JS UI over MQTT."""

    topic_suffix = "driver/nodes"

    @classmethod
    def config_schema(cls) -> list[ConfigField]:
        fields = cls._mqtt_fields("zwavejs2mqtt")
        fields.append(ConfigField(
            name="home_id", type="string",
            help="Z-Wave home ID; keeps node identifiers unique per controller",
        ))
        return fields

    def _parse(self, payload) -> list[ImportedDevice]:
        return parse_zwave_nodes(payload, home_id=self._config.get("home_id"))
