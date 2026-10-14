# 06 · API Contract (v3)

Needed by 8:30, since the dashboard and the attack scripts build against this.

**Design:** everything runs in Docker on one laptop. Containers talk by name. The `log-server` **polls** the witness; the witness never calls out. The witness exposes only its API port (no SSH).

```
log-server (victim/ + agent/ + layers/)  --HTTP-->  witness:8000  <--HTTP--  dashboard
log-server  --S3 PutObject only-->  vault:9000 (MinIO)  <--S3 read only--  dashboard (auditor)
```

`WITNESS_URL=http://witness:8000`, `VAULT_URL=http://vault:9000`, set in `docker/docker-compose.yml`.

**Before Round 1 (Steps 0 to 5) everything runs natively, no Docker:** `WITNESS_URL=http://127.0.0.1:8000`, and "log-server" means the local `victim/` + `agent/` processes. Routes and bodies are identical, so nothing changes when the services move into containers in Step 6.

All amounts: **integer paise**. All timestamps: ISO 8601 UTC string. All keys, hashes and signatures: base64 of raw bytes. Canonical encoding is implemented once in `shared/` and imported everywhere — never reimplemented.

## What gets signed (exact field lists)
| Message | Signed payload (canonical encoding via `shared/`) | Signed with |
|---|---|---|
| Entry | every entry field except `signature` (`seq` through `hash`) | agent key |
| Heartbeat | `{platform_id, timestamp}` | agent key |
| Hash-challenge response | `{challenge_id, type, latest_hash, last_seq}` | agent key |
| State-challenge response | `{challenge_id, type, account, balance_paise, last_seq}` | agent key |
| Record-challenge response | `{challenge_id, type, seq, record}` | agent key |
| Sweep response | `{challenge_id, type, records}` | agent key |
| Layer event | every event field except `signature` | agent key |
| Evidence bundle (in vault) | the bundle JSON except `signature` | agent key |
| Break-glass command | `{command_id, action, issued_at, secret}` (`secret` only on unlock) | witness key |

**Genesis:** `GENESIS_PREV_HASH = base64.b64encode(b"\x00" * 32)` = `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, in `shared/`.

---

## Registration (Step 2b)

### `POST /register/agent`
```json
// request
{ "platform_id": "log-server-1", "public_key": "base64..." }
// response
{ "status": "registered", "platform_id": "log-server-1", "key_id": "agent-key-0", "witness_public_key": "base64..." }
```
Witness stores `key_id -> public_key` per `platform_id`. Unknown `key_id` anywhere = rejection `unknown_key_id`, never a crash. The agent keeps `witness_public_key` to verify break-glass commands.

---

## Entries — Check A (Step 2)

### `POST /entries`
```json
// request
{
  "seq": 42, "timestamp": "2026-10-14T08:45:00Z", "event_type": "transaction",
  "txn_id": "txn-00042", "from_account": "acc-1", "to_account": "acc-2",
  "amount_paise": 150000, "from_balance_paise": 4850000, "to_balance_paise": 2150000,
  "prev_hash": "base64...", "key_id": "agent-key-0", "hash": "base64...", "signature": "base64..."
}
// response
{ "status": "accepted" }
{ "status": "rejected", "reason": "chain_break" | "bad_signature" | "sequence_gap" | "non_monotonic_timestamp" | "unknown_key_id" }
```
- Validated against `last_good_seq` / `last_good_hash` (accepted entries only). A rejected entry is stored and raises exactly one alert; it never becomes the reference, so one attack never cascades.
- `non_monotonic_timestamp` = earlier than the last accepted entry. Not "close to now": queued retries arrive late and must not alert.

### Periodic self-check (witness-internal, every 5 s)
Re-hashes stored accepted entries via `shared/`, checks `prev_hash` links and `seq` continuity. Mismatch = direct DB edit: Check A red within 5 s, one alert per broken entry.

### `GET /verify?from_seq=0&to_seq=42`
Recomputes the witness's stored chain for a range; per-entry pass/fail plus a summary.

---

## Heartbeat — Check B (Step 2)

### `POST /heartbeat`
```json
{ "platform_id": "log-server-1", "timestamp": "...", "signature": "base64..." }
// response
{ "status": "ok" }
```
Every 5 s. Counts only if the signature verifies and the timestamp is later than the last accepted heartbeat. No valid heartbeat for >15 s = silence alert (Check B red, Layer 2 event).

---

## Challenges — Checks B and C, Layer 2 (Steps 2 to 3) — log-server polls

### `GET /challenge/poll?platform_id=log-server-1`
```json
{ "challenge": null }
{ "challenge": { "id": "c-101", "type": "hash" } }
{ "challenge": { "id": "c-102", "type": "state", "account": "acc-1" } }
{ "challenge": { "id": "c-103", "type": "record", "seq": 42 } }
{ "challenge": { "id": "c-104", "type": "sweep", "seqs": [1, 2, 3] } }
```
`record` / `sweep`: the agent rebuilds each record from the bank's own row as it is **now** (`txn_id`, `timestamp`, `from_account`, `to_account`, `amount_paise`, `from_balance_paise`, `to_balance_paise`; `null` if the row is gone). The witness compares field by field with its sealed copy. A rolling sweep (`SWEEP_SECONDS`, default 15, batches of `SWEEP_BATCH`) covers every record; the first mismatch triggers a full sweep. Mismatch = `record_mismatch` alert (Check A), `entry_edited` or `entry_deleted`, listed at `GET /mismatches`.
Polled every 2 s. Issued at random times.

### `POST /challenge/response`
```json
{ "challenge_id": "c-101", "type": "hash", "latest_hash": "base64...", "last_seq": 42, "signature": "base64..." }
{ "challenge_id": "c-102", "type": "state", "account": "acc-1", "balance_paise": 4850000, "last_seq": 42, "signature": "base64..." }
{ "challenge_id": "c-103", "type": "record", "seq": 42, "record": { "txn_id": "txn-00042", "amount_paise": 500000, "...": "..." }, "signature": "base64..." }
{ "challenge_id": "c-104", "type": "sweep", "records": [ { "seq": 1, "record": { } }, { "seq": 2, "record": null } ], "signature": "base64..." }
// response
{ "status": "ok" | "mismatch" }
```
No response within 5 s = missed-challenge alert. A state mismatch against the witness's replay at `last_seq` = Check C red.

---

## Layer events + evidence (Steps 7 to 10)

### `POST /events`
Every Layer 1/2/3 event and every evidence bundle reaches the witness here, so the bundle itself is tamper-evident. Producers (wrappers, auditd hook) write unsigned events to the spool via `layers/common/events.py`; the agent adds `key_id` and `signature`.
```json
{
  "event_id": "ev-0007", "layer": 1, "trigger": "wrapper:nano", "tamper_type": null, "detail": { "cmd": "nano app.log", "mode": "deception" },
  "time": "...", "who": { "auid": 1001, "uid": 0, "process": "nano", "exe": "/opt/trip/bin/nano", "src_ip": "172.18.0.6" },
  "bundle_key": "bundles/ev-0007.json", "bundle_hash": "base64...",
  "state": "normal" | "alert" | "frozen",
  "key_id": "agent-key-0", "signature": "base64..."
}
// response
{ "status": "accepted" }
```
`detail` is a free-form object (`cmd`, `mode`, `target`, and for deception the attempted `diff`). `state: "alert"` raises a `layer1_tripwire` alert and sets `/status` layer 1 to `tripped`; `state: "normal"` (e.g. `authorized:nano`, a team member using a valid profile-id) is logged to `/timeline` only. Bad signature or unknown key: `{"status": "rejected", "reason": ...}` and a `forged` alert. `bundle_key`/`bundle_hash` are `null` until the vault exists (Step 7).

`bundle_key` is the object name in the vault. The auditor view checks that the vault object's hash equals `bundle_hash` and that its signature is valid.

### Vault (MinIO, S3 API, not a witness route)
- Bucket `evidence`, object lock on, **compliance** retention, 1 day for the demo. Versioning on (required by object lock).
- `log-server` credential: `s3:PutObject` only. No read, no delete.
- `auditor` credential: read only. Used by the dashboard.
- Prefixes: `stream/` (every log entry as written, the "before" copy), `bundles/` (evidence bundles).

---

## Break glass — Layer 3 (Step 10) — log-server polls

### `POST /breakglass/panic` (dashboard, SOC)
```json
{ "reason": "manual panic", "by": "soc-lead" }
```

### `POST /breakglass/unlock` (dashboard, auditor panel)
```json
{ "shares": [ { "holder": "auditor", "index": 1, "share": "base64..." }, { "holder": "legal", "index": 3, "share": "base64..." } ] }
// response
{ "status": "unlock_issued" } | { "status": "error", "reason": "not_enough_shares" }
```
The witness reconstructs the secret from any 2 shares and queues a signed unlock command. Shares are never typed on the frozen log server.

### `GET /breakglass/poll?platform_id=log-server-1`
```json
{ "command": null }
{ "command": { "command_id": "bg-3", "action": "freeze" | "unlock", "issued_at": "...", "secret": "base64... (unlock only)", "signature": "base64..." } }
```
Log server verifies the witness signature, and for unlock checks `sha256(secret)` against its stored hash, then reverses steps 5, 4, 3 and reports via `POST /events` (`state: normal`). Freeze/FROZEN progress is also reported via `POST /events`.

---

## Dashboard reads (Step 5 watcher, Step 6 dashboard, extended in Step 11)

### `GET /status`
```json
{
  "checks": { "A": "green" | "red", "B": "green" | "red", "C": "green" | "red" },
  "layers": { "1": "on" | "off" | "tripped", "2": "on" | "off" | "tripped", "3": "on" | "off" | "frozen" },
  "state": "normal" | "alert" | "frozen",
  "last_entry_seq": 42, "last_seen": "..."
}
```
`layers` reflect `config/layers.yaml` (each layer switchable for the demo).

### `GET /timeline?since=0`
```json
{ "events": [ { "event_id": "ev-0007", "layer": 1, "trigger": "wrapper:nano", "time": "...", "who": { }, "bundle_key": "bundles/ev-0007.json" } ] }
```

### `GET /alerts?since=0`
```json
{ "alerts": [ { "id": 1, "type": "chain_break", "check": "A", "tamper_type": "entry_edited", "seq": 17, "detail": "field amount_paise: 150000 -> 1500000", "time": "...", "acknowledged": false } ] }
```

**`tamper_type` values (Layer 2 classifier, Step 4):** `entry_edited`, `entry_deleted`, `entries_reordered`, `entry_replayed`, `entry_inserted`, `backdated`, `forged`, `agent_silenced`, `balance_misreported`, `db_edited_without_log`. Layer 1 and 3 events use `tamper_type: null`. For `entry_edited`, `detail` names the field and old -> new value once the vault exists.

### `POST /alerts/{id}/ack`
```json
{ "note": "confirmed as test attack" }
```

### `GET /export`
Full auditor report (HTML or JSON, Jaganath's call).

---

## Error shape (all endpoints)
```json
{ "status": "error", "reason": "short_code", "detail": "one line" }
```
