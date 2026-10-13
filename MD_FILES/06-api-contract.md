# 06 · API Contract

Needed by 8:30 (Checkpoint 1), since Jaganath's dashboard and the feed both build against this.

**Design choice:** the agent and feed **poll** the witness instead of the witness calling them. Only the witness (Laptop B) needs an inbound firewall rule. Laptop A and C only make outbound calls.

```
Laptop A (victim/ + agent/)  --HTTP-->  Laptop B (witness/ + dashboard/, holds shared/)  <--HTTP--  Laptop C (feed/)
```

Base URLs: set `WITNESS_URL` as an env var on all 3 laptops, e.g. `http://192.168.1.2:8000` (write the real IP on the sticky note at 8:00).

All amounts: **integer paise**. All timestamps: ISO 8601 UTC string. All keys and hashes: base64-encoded raw bytes. All signatures: base64-encoded Ed25519 signature over the canonical-encoded bytes of the fields listed in **What gets signed** below. Canonical encoding is implemented once in `shared/` and imported by both `agent/` and `witness/` — never reimplemented on either side.

## What gets signed (exact field lists)
| Message | Signed payload (canonical encoding via `shared/`) | Signed with |
|---|---|---|
| Entry | every entry field except `signature` (`seq` through `hash`) | agent's current key |
| Heartbeat | `{platform_id, timestamp}` | agent's current key |
| Hash-challenge response | `{challenge_id, type, latest_hash, last_seq}` | agent's current key |
| State-challenge response | `{challenge_id, type, account, balance_paise, last_seq}` | agent's current key |
| Feed confirmation | `{txn_id, from_account, to_account, amount_paise, confirmed_at}` | feed's key |
| Key rotation | `{platform_id, new_public_key}` | agent's OLD key |
| Receipt / anchor | the receipt or anchor fields except `signature` | witness key |

**Genesis:** `GENESIS_PREV_HASH = base64.b64encode(b"\x00" * 32)` = `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, defined in `shared/`. The `seq = 0` entry uses it as `prev_hash`.

---

## Registration (Step 0, after the witness is up — before any entry or confirmation)

### `POST /register/agent`
Called once by the agent at startup, before it sends its first entry or heartbeat.
```json
// request
{ "platform_id": "victim-bank-1", "public_key": "base64..." }
// response
{ "status": "registered", "platform_id": "victim-bank-1", "key_id": "agent-key-0" }
```
Witness stores `key_id -> public_key` per `platform_id`. It's a growing map (rotation adds to it), not a single current key.

### `POST /register/feed`
Called once by the feed at startup, before it sends its first confirmation.
```json
// request
{ "feed_id": "settlement-1", "public_key": "base64..." }
// response
{ "status": "registered", "feed_id": "settlement-1", "key_id": "feed-key-0" }
```

Witness refuses `/entries`, `/heartbeat` and `/feed/confirmations` from any key it hasn't registered. An unrecognised `key_id` is a rejection (`reason: "unknown_key_id"`), never a crash.

---

## Entries (Step 3 to 4)

### `POST /entries`
```json
// request
{
  "seq": 42,
  "timestamp": "2026-10-14T08:45:00Z",
  "event_type": "transaction",
  "txn_id": "txn-00042",
  "from_account": "acc-1",
  "to_account": "acc-2",
  "amount_paise": 150000,
  "from_balance_paise": 4850000,
  "to_balance_paise": 2150000,
  "prev_hash": "base64...",
  "key_id": "agent-key-3",
  "hash": "base64...",
  "signature": "base64..."
}
// response (accepted)
{ "status": "accepted", "receipt": { "seq": 42, "hash": "base64...", "witness_time": "...", "signature": "base64..." } }
// response (rejected)
{ "status": "rejected", "reason": "chain_break" | "bad_signature" | "sequence_gap" | "non_monotonic_timestamp" | "unknown_key_id" }
```
**Checked against the last accepted entry.** The witness tracks `last_good_seq` / `last_good_hash` separately from "last entry received". Only accepted entries advance them. Every new entry is validated against `last_good_*`, never against a rejected entry. A rejected entry is stored and raises exactly one alert, so one attack never cascades into failing every later entry.

`non_monotonic_timestamp` fires only when an entry's timestamp is **earlier than the last accepted entry's timestamp** — not based on how far the timestamp is from the witness's current wall clock. This matters because retried entries (queued during a disconnect, see `02-flow.md` Step 3's fallback) can legitimately arrive late with an older-but-still-increasing timestamp; that must not alert.

A rejected entry is still stored and raises an alert — rejection is the alert, not a silent drop.

---

## Heartbeat (Step 4, liveness only)

### `POST /heartbeat`
```json
// request
{ "platform_id": "victim-bank-1", "timestamp": "...", "signature": "base64..." }
// response
{ "status": "ok" }
```
Agent sends this every 5 seconds regardless of transaction volume. A heartbeat only resets the silence timer if its signature verifies against the registered key for `platform_id` **and** its timestamp is later than the previous accepted heartbeat (no replays). Unsigned, badly signed or replayed heartbeats don't count. Missing valid heartbeats for >15s = silence alert. (No `profile_hash`: profiles are slide-only.) This is the only "is the agent still alive right now" check — entry timestamps (above) check ordering, not freshness.

---

## Challenges (Step 7, 13) — agent polls, doesn't get called

### `GET /challenge/poll?platform_id=victim-bank-1`
```json
// response, nothing pending
{ "challenge": null }
// response, hash challenge
{ "challenge": { "id": "c-101", "type": "hash" } }
// response, state challenge (Check 2)
{ "challenge": { "id": "c-102", "type": "state", "account": "acc-1" } }
```
Agent polls every 2 seconds.

### `POST /challenge/response`
```json
// hash challenge response
{ "challenge_id": "c-101", "type": "hash", "latest_hash": "base64...", "last_seq": 42, "signature": "base64..." }
// state challenge response (Check 2)
{ "challenge_id": "c-102", "type": "state", "account": "acc-1", "balance_paise": 4850000, "last_seq": 42, "signature": "base64..." }
// response
{ "status": "ok" | "mismatch" }
```
No response within 5 seconds of a challenge being issued = missed-challenge alert.

---

## Feed confirmations (Step 8, Check 3)

### `POST /feed/confirmations`
```json
// request
{
  "txn_id": "txn-00042",
  "from_account": "acc-1",
  "to_account": "acc-2",
  "amount_paise": 150000,
  "confirmed_at": "2026-10-14T08:45:05Z",
  "key_id": "feed-key-0",
  "signature": "base64..."
}
// response
{ "status": "accepted" }
```
Matching window: 30 seconds either side. Unmatched after the window = alert (A13 if entry exists with no confirmation, "missing entry" if confirmation exists with no entry).

---

## Verification (Step 4 core, Step 12 full UI)

### `GET /verify?from_seq=0&to_seq=42`
Recomputes the witness's **own** stored chain for a range and returns per-entry pass/fail plus a summary. **Available from Step 4** as a raw endpoint. The Step 12 auditor tab is just a UI on this route. It does not compare against the agent; use `/verify/compare` for that.

### `POST /verify/compare` (Step 4)
```json
// request: the agent's local entries, same shape as /entries payloads
{ "entries": [ ] }
// response
{ "mismatches": [ { "seq": 17, "reason": "missing_locally" | "hash_mismatch" | "extra_locally" } ], "match_count": 41 }
```
Used by `attacks/compare_local.py` (reads the agent's local SQLite, posts it here, prints mismatches). This is what T2d, A3 and A7 run against.

---

## Periodic self-check (Step 4, witness-internal, no route)
Every 5 seconds the witness re-reads its stored **accepted** entries, recomputes each `hash` from its fields via `shared/`, and checks `prev_hash` links and `seq` continuity. A mismatch means the witness DB was edited directly (A1, A2): chain-break alert, Layer 1 red within 5 s, no new entry needed. One alert per broken entry (de-duplicated), not one every cycle. Rejected entries are skipped (they're stored as evidence, not part of the chain).

This does **not** defend against a compromised witness (A10): an attacker with the witness could also silence this job. That's what receipts and anchors are for.

---

## Key rotation (Step 10)

### `POST /keys/rotate`
```json
// request (signed with the OLD private key over {platform_id, new_public_key})
{ "platform_id": "victim-bank-1", "new_public_key": "base64...", "signature": "base64..." }
// response
{ "status": "rotated", "key_id": "agent-key-1", "effective_from_seq": 101 }
```
Witness verifies the signature against the currently registered key for that `platform_id`. The old `key_id` stays valid only for entries with `seq < effective_from_seq`; new entries must use the new `key_id`.

---

## Anchor (Step 11) — Laptop C pulls, witness never calls out

### `GET /anchor/latest`
```json
{ "chain_head_hash": "base64...", "last_seq": 100, "anchored_at": "...", "signature": "base64..." }
```
Laptop C polls every few minutes and appends the response to its local anchor file.

---

## Dashboard reads (Step 6, 12) — polled by `dashboard/`

### `GET /status`
```json
{
  "layer1": "green" | "red",
  "layer2": "green" | "red",
  "layer3": "green" | "red",
  "last_entry_seq": 42,
  "last_seen": "..."
}
```

### `GET /alerts?since=0`
```json
{ "alerts": [ { "id": 1, "type": "chain_break", "seq": 17, "detail": "...", "time": "...", "acknowledged": false } ] }
```

### `POST /alerts/{id}/ack`
```json
{ "note": "confirmed as test attack" }
```

### `GET /export`
Returns the full auditor report (HTML or JSON, Jaganath's call).

---

## Error shape (all endpoints)
```json
{ "status": "error", "reason": "short_code", "detail": "one line" }
```
