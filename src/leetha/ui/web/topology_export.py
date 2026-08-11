"""Server-side topology rendering and read-only share keys.

The dashboard draws the topology in the browser, which is fine interactively
but useless for reports, tickets, or handing a map to someone who has no
account. Rendering SVG on the server makes the graph fetchable with curl and
embeddable in documentation.

Share keys are deliberately kept separate from API tokens: a leaked share
link must never grant API access, so it is stored in its own file and is only
ever consulted by the share endpoints.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from html import escape
from pathlib import Path

SHARE_KEY_PREFIX = "lsk_"
_SHARE_FILENAME = "share-key"
_KEY_BYTES = 24


# ---------------------------------------------------------------------------
# Share keys
# ---------------------------------------------------------------------------

def _share_file(data_dir: Path) -> Path:
    return Path(data_dir) / _SHARE_FILENAME


def create_share_key(data_dir: Path) -> str:
    """Generate a share key, persist only its digest, return the raw key."""
    raw = SHARE_KEY_PREFIX + secrets.token_urlsafe(_KEY_BYTES)
    path = _share_file(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(hashlib.sha256(raw.encode()).hexdigest() + "\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return raw


def revoke_share_key(data_dir: Path) -> bool:
    """Delete the stored share key. True when one was present."""
    path = _share_file(data_dir)
    try:
        path.unlink()
        return True
    except OSError:
        return False


def share_key_exists(data_dir: Path) -> bool:
    try:
        return _share_file(data_dir).is_file()
    except OSError:
        return False


def verify_share_key(candidate: str, data_dir: Path) -> bool:
    """Constant-time check of a presented share key."""
    if not candidate:
        return False
    try:
        stored = _share_file(data_dir).read_text().strip()
    except OSError:
        return False
    if not stored:
        return False
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    return hmac.compare_digest(digest, stored)


# ---------------------------------------------------------------------------
# SVG rendering
# ---------------------------------------------------------------------------

_TYPE_COLOURS = {
    "internet": "#64748b",
    "router": "#f59e0b",
    "gateway": "#f59e0b",
    "switch": "#0ea5e9",
    "access_point": "#0ea5e9",
    "network_device": "#0ea5e9",
    "server": "#8b5cf6",
    "virtual_machine": "#8b5cf6",
    "computer": "#22c55e",
    "workstation": "#22c55e",
    "smartphone": "#22c55e",
    "printer": "#e879f9",
    "ip_camera": "#ef4444",
    "plc": "#ef4444",
    "ics_device": "#ef4444",
    "iot": "#14b8a6",
    "smart_speaker": "#14b8a6",
    "smart_home": "#14b8a6",
}
_DEFAULT_COLOUR = "#94a3b8"

_WIDTH = 1400
_ROW_HEIGHT = 150
_NODE_R = 26


def _colour_for(node: dict) -> str:
    for key in ("type", "device_type", "category"):
        value = (node.get(key) or "").lower()
        if value in _TYPE_COLOURS:
            return _TYPE_COLOURS[value]
    return _DEFAULT_COLOUR


def _label_for(node: dict) -> str:
    for key in ("hostname", "manufacturer", "ip", "id"):
        value = node.get(key)
        if value:
            return str(value)
    return "unknown"


def _layout(nodes: list[dict]) -> dict[str, tuple[float, float]]:
    """Group nodes into rows by role so the picture reads top-down.

    Infrastructure sits at the top, endpoints below it. Nodes inside a row
    are spread evenly; this is intentionally a static layout rather than a
    force simulation so the output is deterministic and diffable.
    """
    tiers: list[list[dict]] = [[], [], []]
    for node in nodes:
        kind = (node.get("type") or node.get("device_type") or "").lower()
        if kind in ("internet",):
            tiers[0].append(node)
        elif kind in ("router", "gateway", "switch", "access_point", "network_device"):
            tiers[1].append(node)
        else:
            tiers[2].append(node)

    positions: dict[str, tuple[float, float]] = {}
    for row, tier in enumerate(tiers):
        if not tier:
            continue
        # Wrap wide tiers so labels do not collide.
        per_row = max(1, min(len(tier), 9))
        for index, node in enumerate(tier):
            sub_row, col = divmod(index, per_row)
            count = min(per_row, len(tier) - sub_row * per_row)
            step = _WIDTH / (count + 1)
            x = step * (col + 1)
            y = 90 + (row * 2 + sub_row) * _ROW_HEIGHT
            positions[str(node.get("id"))] = (x, y)
    return positions


def render_topology_svg(graph: dict, title: str = "Leetha network topology") -> str:
    """Render a topology graph dict into a standalone SVG document."""
    nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]
    positions = _layout(nodes)

    height = int(max(
        [y for _x, y in positions.values()] or [0]
    )) + 140

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_WIDTH}" '
        f'height="{height}" viewBox="0 0 {_WIDTH} {height}" '
        f'font-family="system-ui, sans-serif">',
        f'<title>{escape(title)}</title>',
        f'<rect width="{_WIDTH}" height="{height}" fill="#0f172a"/>',
        f'<text x="24" y="40" fill="#e2e8f0" font-size="22">{escape(title)}</text>',
        f'<text x="24" y="62" fill="#94a3b8" font-size="13">'
        f'{len(nodes)} devices · {len(edges)} links</text>',
    ]

    # Edges first so nodes draw on top.
    for edge in edges:
        src = positions.get(str(edge.get("source", edge.get("from"))))
        dst = positions.get(str(edge.get("target", edge.get("to"))))
        if not src or not dst:
            continue
        parts.append(
            f'<line x1="{src[0]:.1f}" y1="{src[1]:.1f}" '
            f'x2="{dst[0]:.1f}" y2="{dst[1]:.1f}" '
            f'stroke="#334155" stroke-width="1.5"/>'
        )

    for node in nodes:
        node_id = str(node.get("id"))
        pos = positions.get(node_id)
        if not pos:
            continue
        x, y = pos
        colour = _colour_for(node)
        label = _label_for(node)
        if len(label) > 22:
            label = label[:21] + "…"
        ip = node.get("ip") or ""
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{_NODE_R}" fill="{colour}" '
            f'stroke="#0f172a" stroke-width="3"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y + _NODE_R + 18:.1f}" fill="#e2e8f0" '
            f'font-size="12" text-anchor="middle">{escape(label)}</text>'
        )
        if ip:
            parts.append(
                f'<text x="{x:.1f}" y="{y + _NODE_R + 33:.1f}" fill="#94a3b8" '
                f'font-size="11" text-anchor="middle">{escape(str(ip))}</text>'
            )

    parts.append("</svg>")
    return "".join(parts)


# Kept for callers that want a deterministic pixel size without parsing SVG.
def svg_dimensions(graph: dict) -> tuple[int, int]:
    nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    positions = _layout(nodes)
    height = int(max([y for _x, y in positions.values()] or [0])) + 140
    return _WIDTH, max(height, 200)


__all__ = [
    "create_share_key", "revoke_share_key", "share_key_exists",
    "verify_share_key", "render_topology_svg", "svg_dimensions",
    "SHARE_KEY_PREFIX",
]
