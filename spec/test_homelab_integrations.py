"""Integrations adapted from Homelable: Proxmox, Zigbee/Z-Wave, topology sharing.

The two importers cover devices passive capture cannot reach -- virtual
guests whose MACs live only in hypervisor config, and Zigbee/Z-Wave nodes
that never touch IP at all.
"""
from __future__ import annotations

import json

import pytest

from leetha.inventory.importers.proxmox import extract_macs
from leetha.inventory.importers.mqtt_smarthome import (
    normalise_eui64, parse_zigbee2mqtt_devices, parse_zwave_nodes,
)
from leetha.inventory.registry import get_all_importers
from leetha.ui.web import topology_export as tex


def test_new_importers_are_registered():
    # spec/inventory/test_registry.py calls clear_registry() without
    # restoring it, so re-run the decorators before asserting rather than
    # depending on whatever earlier tests left in the global registry.
    import importlib
    import leetha.inventory.importers as importers_pkg

    importlib.reload(importlib.import_module(
        "leetha.inventory.importers.proxmox"))
    importlib.reload(importlib.import_module(
        "leetha.inventory.importers.mqtt_smarthome"))
    importlib.reload(importers_pkg)

    names = set(get_all_importers())
    assert {"proxmox", "zigbee2mqtt", "zwave_js"} <= names


# ---------------------------------------------------------------------------
# Proxmox
# ---------------------------------------------------------------------------

def test_extract_macs_from_qemu_config():
    conf = {
        "net0": "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,tag=20",
        "net1": "e1000=AA:BB:CC:DD:EE:02,bridge=vmbr1",
        "scsi0": "local-lvm:vm-101-disk-0,size=32G",
        "cores": 4,
    }
    assert extract_macs(conf) == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]


def test_extract_macs_from_lxc_config():
    """Containers use hwaddr= rather than a NIC-model key."""
    conf = {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:22:33:44,ip=dhcp,type=veth"}
    assert extract_macs(conf) == ["bc:24:11:22:33:44"]


def test_extract_macs_ignores_guests_without_nics():
    assert extract_macs({"cores": 2, "memory": 1024}) == []
    assert extract_macs({}) == []


def test_extract_macs_skips_malformed_values():
    assert extract_macs({"net0": "virtio=not-a-mac,bridge=vmbr0"}) == []
    assert extract_macs({"net0": 12345}) == []


# ---------------------------------------------------------------------------
# Zigbee2MQTT
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("0x00124b0021f8ab12", "00:12:4b:00:21:f8:ab:12"),
    ("00124b0021f8ab12", "00:12:4b:00:21:f8:ab:12"),
    ("00:17:88:01:0b:2c:3d:4e", "00:17:88:01:0b:2c:3d:4e"),
    ("0xdeadbeef", None),
    ("", None),
    (None, None),
])
def test_normalise_eui64(raw, expected):
    assert normalise_eui64(raw) == expected


def test_zigbee_import_keeps_vendor_and_skips_coordinator():
    payload = json.dumps([
        {"ieee_address": "0x001788010b2c3d4e", "type": "Router",
         "friendly_name": "Kitchen Bulb", "power_source": "Mains (single phase)",
         "definition": {"vendor": "Philips", "model": "9290012573A",
                        "description": "Hue white and color ambiance"}},
        {"ieee_address": "0x00124b0021f8ab12", "type": "EndDevice",
         "friendly_name": "Front Door", "power_source": "Battery",
         "definition": {"vendor": "Aqara", "model": "MCCGQ11LM"}},
        # The coordinator is the radio itself, not a discovered device.
        {"ieee_address": "0x00124b00aabbccdd", "type": "Coordinator"},
    ])
    devices = parse_zigbee2mqtt_devices(payload)
    assert [d.hostname for d in devices] == ["Kitchen Bulb", "Front Door"]
    assert devices[0].mac == "00:17:88:01:0b:2c:3d:4e"
    assert devices[0].metadata["vendor"] == "Philips"
    assert devices[1].metadata["power_source"] == "Battery"
    assert all(d.source == "zigbee2mqtt" for d in devices)


def test_zigbee_eui64_still_resolves_an_oui_vendor():
    """The top three octets of an EUI-64 are a real IEEE OUI."""
    devices = parse_zigbee2mqtt_devices(
        [{"ieee_address": "0x001788010b2c3d4e", "type": "Router",
          "friendly_name": "Bulb", "definition": {}}]
    )
    assert devices[0].mac.startswith("00:17:88")


def test_zigbee_handles_garbage_payloads():
    assert parse_zigbee2mqtt_devices("not json") == []
    assert parse_zigbee2mqtt_devices({"unexpected": "shape"}) == []
    assert parse_zigbee2mqtt_devices([{"no_address": True}]) == []


# ---------------------------------------------------------------------------
# Z-Wave JS
# ---------------------------------------------------------------------------

def test_zwave_import_skips_controller_and_keys_by_home_id():
    payload = json.dumps({"nodes": [
        {"id": 1, "isControllerNode": True, "name": "Controller"},
        {"id": 7, "name": "Dimmer", "manufacturer": "Inovelli",
         "productLabel": "LZW31-SN", "isRouting": True, "status": "Alive"},
        {"id": 12, "name": "Sensor", "manufacturer": "Aeotec",
         "productLabel": "ZW100", "isRouting": False, "status": "Asleep"},
    ]})
    devices = parse_zwave_nodes(payload, home_id="0xD41C9F3A")
    assert [d.hostname for d in devices] == ["Dimmer", "Sensor"]
    # Node IDs are only unique per controller, so the home ID is part of the key.
    assert devices[0].mac == "zwave:0xd41c9f3a:7"
    assert devices[0].metadata["device_role"] == "router"
    assert devices[1].metadata["device_role"] == "end_device"


def test_zwave_accepts_a_nodeid_keyed_mapping():
    payload = {"7": {"id": 7, "name": "Dimmer", "isRouting": True}}
    devices = parse_zwave_nodes(payload, home_id="abc")
    assert len(devices) == 1
    assert devices[0].mac == "zwave:abc:7"


def test_zwave_handles_garbage_payloads():
    assert parse_zwave_nodes("not json") == []
    assert parse_zwave_nodes([{"no_id": True}]) == []


# ---------------------------------------------------------------------------
# Topology export + share keys
# ---------------------------------------------------------------------------

_GRAPH = {
    "nodes": [
        {"id": "internet", "type": "internet"},
        {"id": "aa:bb:cc:dd:ee:01", "type": "router", "hostname": "gw", "ip": "10.0.0.1"},
        {"id": "aa:bb:cc:dd:ee:02", "type": "printer",
         "manufacturer": "HP", "ip": "10.0.0.5"},
    ],
    "edges": [{"source": "internet", "target": "aa:bb:cc:dd:ee:01"},
              {"source": "aa:bb:cc:dd:ee:01", "target": "aa:bb:cc:dd:ee:02"}],
}


def test_render_topology_svg_is_well_formed():
    import xml.etree.ElementTree as ET
    svg = tex.render_topology_svg(_GRAPH)
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "gw" in svg and "10.0.0.5" in svg


def test_render_topology_svg_escapes_hostile_labels():
    """Device-supplied hostnames must not break out into markup."""
    graph = {"nodes": [{"id": "x", "type": "computer",
                        "hostname": '<script>alert(1)</script>'}], "edges": []}
    svg = tex.render_topology_svg(graph)
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_render_topology_svg_handles_an_empty_graph():
    import xml.etree.ElementTree as ET
    ET.fromstring(tex.render_topology_svg({"nodes": [], "edges": []}))


def test_share_key_round_trip(tmp_path):
    assert tex.share_key_exists(tmp_path) is False
    key = tex.create_share_key(tmp_path)
    assert key.startswith(tex.SHARE_KEY_PREFIX)
    assert tex.share_key_exists(tmp_path) is True
    assert tex.verify_share_key(key, tmp_path) is True
    assert tex.verify_share_key("lsk_wrong", tmp_path) is False
    assert tex.verify_share_key("", tmp_path) is False


def test_share_key_is_stored_hashed_not_plaintext(tmp_path):
    key = tex.create_share_key(tmp_path)
    stored = (tmp_path / "share-key").read_text().strip()
    assert key not in stored
    assert len(stored) == 64  # sha256 hex


def test_rotating_invalidates_the_previous_key(tmp_path):
    old = tex.create_share_key(tmp_path)
    new = tex.create_share_key(tmp_path)
    assert old != new
    assert tex.verify_share_key(old, tmp_path) is False
    assert tex.verify_share_key(new, tmp_path) is True


def test_revoke_share_key(tmp_path):
    key = tex.create_share_key(tmp_path)
    assert tex.revoke_share_key(tmp_path) is True
    assert tex.verify_share_key(key, tmp_path) is False
    assert tex.revoke_share_key(tmp_path) is False  # already gone


def test_share_routes_are_exempt_from_api_auth_but_mutations_are_admin():
    from leetha.auth.middleware import _is_exempt
    from leetha.auth.roles import requires_admin

    # The read-only snapshot carries its own key.
    assert _is_exempt("/share/lsk_abc/topology.svg") is True
    # Minting or revoking a link is an admin action.
    assert requires_admin("POST", "/api/topology/share") is True
    assert requires_admin("DELETE", "/api/topology/share") is True
