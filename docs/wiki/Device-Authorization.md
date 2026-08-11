# Device Authorization

Leetha tracks every discovered device through a tri-state **authorization** lifecycle. The state controls how loudly leetha alerts when it sees that device:

| State | Effect on `new_host` | Meaning |
|---|---|---|
| `approved` | none | You have confirmed this device *and* confirmed that leetha's fingerprint of it is accurate. |
| `unapproved` | none | Default. Nobody has reviewed this device yet. |
| `rejected` | CRITICAL | Known-bad. You don't want this device here — escalate every finding. |

Alert severity is **not** driven by authorization (apart from `rejected`). It is
decided by the [learning window](#the-learning-window): whether leetha was still
learning the network when the device first appeared. Approving a device is a
statement about *identification accuracy*, not a mute button.

The state lives in the `devices.authorization` column. Every transition is recorded in a separate `authorization_history` table as a tamper-resistant audit trail.

---

## Why It Exists

Without authorization, leetha would fire `new_host` for every device it discovers, forever. On an established network with hundreds of existing hosts, that's pure noise. Authorization lets you:

- **Record verified ground truth** — mark that a human checked the device and that leetha's inferred vendor/OS/type is correct, rather than merely inferred.
- **Escalate known-bad devices** — reject a specific MAC to promote its findings to CRITICAL.
- **Audit who decided what** — every state change records the acting token id and an optional reason.

---

## State Transitions

Valid transitions (any state can move to any other state):

```
                 approve
              ┌────────────►
              │
unapproved ◄──┤                  approved
              │    revoke
              │◄────────────
              │
              │    reject                      approve
              └────────────►  rejected   ◄──────────────
              ◄──────────────            ──────────────►
                   revoke                      reject
```

A same-state transition is a no-op (no history row written).

**Auto-resolve on approve**: when a device transitions to `approved`, leetha's store layer marks any currently-unresolved `new_host` finding for that MAC as `resolved=1`. Approving a device silences the warning it just produced.

---

## CLI

Single device:

```bash
leetha device approve bc:df:58:1c:3d:c8 --reason "onboarded"
leetha device reject  bc:df:58:1c:3d:c8 --reason "not authorized"
leetha device revoke  bc:df:58:1c:3d:c8
```

Bulk:

```bash
leetha baseline status              # learning state + authorization counts
leetha baseline finish              # stop learning now, start alerting
leetha baseline clear-attestations  # undo approvals from the removed bulk command
leetha baseline reset               # revoke every device back to unapproved
```

> **Removed:** `leetha baseline set`. It approved every device at once, which
> recorded a human attestation for devices nobody had reviewed. Silencing a
> freshly-deployed sensor is now automatic — see below.

## The Learning Window

Leetha stays quiet while it is still discovering a network, then escalates
devices that arrive afterwards:

| Situation | `new_host` severity |
|---|---|
| Device found while leetha was still learning | INFO |
| Device arrives after the network was learned | WARNING |
| Device is `rejected` by a human | CRITICAL |

The window closes when device discovery goes quiet — no previously-unseen MAC
for `max(quiet period, 20% of observation time)` — rather than after a fixed
duration. That scales to the *size* of the network instead of the length of the
session, so the same rule serves a one-hour assessment run and a multi-week
deployment. A hard cap ends learning even on a network that never settles.

If a cluster of unseen devices appears at once after a quiet spell, leetha reads
that as the network waking up and re-enters learning rather than firing a
warning per device. A long sensor outage does the same on restart: leetha was
not watching, so it cannot claim what it now sees is new.

Configure it in **Settings → Discovery & Alerting**, or force it with
`leetha baseline finish`.

### `discovery_context`

Each device records the sensor's learning state at the moment it was first
seen, in `devices.discovery_context`:

| Value | Meaning |
|---|---|
| `learning` | Found while leetha was still discovering the network |
| `monitored` | Arrived after the network was learned |

It is stamped once and never overwritten, so severity cannot be re-graded by a
later sighting or by changing the settings. Devices that predate the upgrade
backfill to `learning` — everything already known is pre-existing inventory.

Filter on it from the Devices page, or via the API:

```
GET /api/devices?discovery_context=monitored
```

which answers "what has appeared since leetha learned this network?".

Sample output of `baseline status`:

```
approved=27 unapproved=3 rejected=0
last_baseline_at=2026-04-20T01:18:21.014426+00:00
```

---

## REST API

### Per-device mutation (admin-only)

| Verb | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/devices/{mac}/approve` | `{"reason": "..."}` (optional) | Updated device JSON |
| POST | `/api/devices/{mac}/reject`  | `{"reason": "..."}` | Updated device JSON |
| POST | `/api/devices/{mac}/revoke`  | `{"reason": "..."}` | Updated device JSON |

The actor recorded in the history row is the authenticated token id pulled from `request.scope["auth_token_id"]`. Unauthenticated calls (auth disabled) record `actor="anonymous"`.

### Bulk mutation (admin-only)

```
POST /api/devices/bulk/authorization
Content-Type: application/json

{
  "action": "approve",        // or "reject" | "revoke"
  "macs": ["aa:bb:...", ...], // 1 ≤ len ≤ 500
  "reason": "..."             // optional
}
```

Returns:

```json
{"updated": 27, "missing": ["ff:ff:ff:ff:ff:ff"], "action": "approve"}
```

`missing` lists MACs not present in either the `hosts` or `devices` tables (a host that exists only in `hosts` but not yet in `devices` is auto-created before the mutation applies).

### Baseline (admin-only)

| Verb | Path | Effect |
|---|---|---|
| POST | `/api/baseline/finish` | Close the learning window. Touches no device rows. |
| POST | `/api/baseline/restart-learning` | Re-enter learning. |
| POST | `/api/baseline/clear-attestations` | Revert approvals whose latest history entry has reason `"baseline"`. |
| POST | `/api/baseline/reset` | `UPDATE devices SET authorization='unapproved' WHERE authorization != 'unapproved'`, one history row per touched device with reason `"baseline-reset"` |

### Status (analyst)

```
GET /api/baseline/status
→ {"approved": 27, "unapproved": 3, "rejected": 0, "last_baseline_at": "..."}
```

### Audit history (analyst)

```
GET /api/devices/{mac}/authorization/history?limit=100
→ {"mac": "...", "history": [
    {"id": 14, "mac": "...", "previous_state": "unapproved",
     "new_state": "approved", "actor": "1", "reason": "onboarded",
     "timestamp": "2026-04-20T01:18:21Z"},
    ...
  ]}
```

Limit defaults to 100, max 1000. Newest first. Returns 404 if the MAC is unknown in both tables and has no history rows.

---

## Role Enforcement

Per `leetha/auth/roles.py`:

- All authorization-mutating endpoints (`approve`, `reject`, `revoke`, bulk authorization, `baseline reset`, `baseline finish`, `baseline clear-attestations`) require **admin** role.
- Read endpoints (`baseline/status`, authorization history) are available to **analyst** tokens.

Analyst tokens that hit an admin endpoint get HTTP 403 with `{"error": "Admin access required."}`.

Authorization is orthogonal to the existing `alert_status` (new / known / suspicious / self) which reflects how leetha categorizes a device's *identity*. Both can coexist — a device can be `alert_status=known` and `authorization=rejected`, meaning "I know what this device is, I just don't want it on my network."

---

## Web UI

- **Device drawer → Labels tab → Authorization panel** — the badge shows the current state; the reason textbox + three buttons (Approve / Reject / Revoke) perform the transition. The actor is pulled from your authenticated session.
- **Devices list → row checkboxes** — select one or more rows to reveal the bulk action toolbar with Approve / Reject / Revoke buttons.
- **Settings → Discovery & Alerting** — learning mode, quiet period, maximum window, a live status line, and `Finish learning now`. The old "Set baseline" banner on the Devices page has been removed.
- **Sticky drawer header** — AuthorizationBadge is always visible at the top of the drawer, regardless of active tab.

---

## Schema

```sql
CREATE TABLE devices (
  mac                TEXT PRIMARY KEY,
  ...
  authorization      TEXT NOT NULL DEFAULT 'unapproved',
  authorized_at      TEXT,
  authorized_by      TEXT,
  ...
);

CREATE TABLE authorization_history (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  mac            TEXT NOT NULL,
  previous_state TEXT NOT NULL,
  new_state      TEXT NOT NULL,
  actor          TEXT NOT NULL,
  reason         TEXT,
  timestamp      TEXT NOT NULL,
  FOREIGN KEY (mac) REFERENCES devices(mac)
);
CREATE INDEX idx_auth_hist_mac ON authorization_history(mac);
CREATE INDEX idx_devices_authorization ON devices(authorization);
```

The `authorization` column is filterable and sortable via `/api/devices?authorization=rejected&sort=authorization`. For rows where the `devices` row doesn't exist yet, the API defaults `authorization` to `unapproved` (via `COALESCE` in the list query) so the state model is consistent regardless of whether a hosts-only device has been materialized into `devices` yet.
