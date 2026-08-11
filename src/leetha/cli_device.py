"""Phase A.1 — leetha device CLI: custom-property set + tag add/remove."""

from __future__ import annotations

import sys

from leetha.config import get_config
from leetha.store.database import Database


_VALID_CRITICALITY = {"low", "medium", "high", "critical"}


async def handle_device_command(parsed_args) -> int:
    """Dispatch the 'device' subcommand. Returns shell exit code."""
    cfg = get_config()
    db = Database(cfg.db_path)
    await db.initialize()
    try:
        action = getattr(parsed_args, "device_action", None)
        if action == "set":
            return await _cmd_set(db, parsed_args)
        if action == "tags":
            sub = getattr(parsed_args, "tags_action", None)
            if sub == "add":
                return await _cmd_tags_add(db, parsed_args)
            if sub == "remove":
                return await _cmd_tags_remove(db, parsed_args)
            print("Usage: leetha device tags {add|remove} <mac> <tag>")
            return 2
        if action in ("approve", "reject", "revoke"):
            return await _cmd_authorize(db, parsed_args, action)
        print("Usage: leetha device {set|tags|approve|reject|revoke} ...")
        return 2
    finally:
        await db.close()


async def handle_baseline_command(parsed_args) -> int:
    """Dispatch the 'baseline' subcommand (Phase A.2)."""
    cfg = get_config()
    db = Database(cfg.db_path)
    await db.initialize()
    try:
        action = getattr(parsed_args, "baseline_action", None)
        if action == "set":
            # Removed rather than repurposed: reusing the name for the new
            # policy action would silently change what existing scripts do.
            print(
                "'baseline set' has been removed.\n"
                "\n"
                "It bulk-approved every device, which recorded that a human had "
                "verified each one when nobody had looked. Alert noise is now "
                "handled automatically: leetha stays quiet while it learns the "
                "network and only escalates devices that arrive afterwards.\n"
                "\n"
                "  leetha baseline status    show the learning window\n"
                "  leetha baseline finish    stop learning now, start alerting\n",
                file=sys.stderr,
            )
            return 2
        if action == "finish":
            await db.close_learning_window()
            print("Learning finished. New devices from now on grade as WARNING.")
            return 0
        if action == "restart":
            await db.reopen_learning_window()
            print("Re-entered learning. New devices grade as INFO until it closes.")
            return 0
        if action == "reset":
            touched = await db.baseline_reset(actor="baseline-reset")
            print(f"Baseline reset: returned {touched} device(s) to unapproved.")
            return 0
        if action == "clear-attestations":
            reverted = await db.clear_baseline_attestations()
            print(f"Cleared {reverted} bulk-approval attestation(s).")
            return 0
        if action == "status":
            state = await db.get_sensor_state()
            status = await db.baseline_status()
            learning = state["window_closed_at"] is None
            print(f"learning={'yes' if learning else 'no'}")
            print(f"watching_since={state['first_capture_at']}")
            if not learning:
                print(f"learned_at={state['window_closed_at']}")
            print(f"last_new_device={state['last_discovery_at']}")
            print(
                f"approved={status['approved']} "
                f"unapproved={status['unapproved']} "
                f"rejected={status['rejected']}"
            )
            return 0
        print(
            "Usage: leetha baseline "
            "{status|finish|restart|reset|clear-attestations}"
        )
        return 2
    finally:
        await db.close()


async def _cmd_authorize(db: Database, args, action: str) -> int:
    mac = args.mac
    existing = await db.get_device(mac)
    if existing is None:
        print(f"Device {mac} not found.")
        return 1
    actor = getattr(args, "actor", None) or "cli"
    reason = getattr(args, "reason", None)
    if action == "approve":
        dev = await db.approve_device(mac, actor=actor, reason=reason)
    elif action == "reject":
        dev = await db.reject_device(mac, actor=actor, reason=reason)
    else:  # revoke
        dev = await db.revoke_device(mac, actor=actor, reason=reason)
    assert dev is not None
    print(f"{mac} → {dev.authorization} (by {actor})")
    return 0


async def _cmd_set(db: Database, args) -> int:
    mac = args.mac
    existing = await db.get_device(mac)
    if existing is None:
        print(f"Device {mac} not found.")
        return 1

    updates: dict = {}
    for key in ("owner", "location", "notes"):
        val = getattr(args, key, None)
        if val is not None:
            updates[key] = val

    criticality = getattr(args, "criticality", None)
    if criticality is not None:
        if criticality not in _VALID_CRITICALITY:
            print(f"Invalid criticality: {criticality!r}. "
                  f"Choose from {sorted(_VALID_CRITICALITY)}.")
            return 2
        updates["criticality"] = criticality

    tags_raw = getattr(args, "tags", None)
    if tags_raw is not None:
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        updates["tags"] = tags

    if not updates:
        print("No fields to set. Use --owner / --location / --criticality / "
              "--tags / --notes.")
        return 2

    await db.update_device_props(mac, **updates)
    print(f"Updated {mac}: {updates}")
    return 0


async def _cmd_tags_add(db: Database, args) -> int:
    dev = await db.get_device(args.mac)
    if dev is None:
        print(f"Device {args.mac} not found.")
        return 1
    tag = args.tag.strip()
    if not tag:
        print("Tag must be non-empty.")
        return 2
    new_tags = list(dev.tags)
    if tag not in new_tags:
        new_tags.append(tag)
    await db.update_device_props(args.mac, tags=new_tags)
    print(f"Tags on {args.mac}: {new_tags}")
    return 0


async def _cmd_tags_remove(db: Database, args) -> int:
    dev = await db.get_device(args.mac)
    if dev is None:
        print(f"Device {args.mac} not found.")
        return 1
    new_tags = [t for t in dev.tags if t != args.tag]
    await db.update_device_props(args.mac, tags=new_tags)
    print(f"Tags on {args.mac}: {new_tags}")
    return 0
