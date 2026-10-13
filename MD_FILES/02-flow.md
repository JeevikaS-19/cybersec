# 02 · Build Flow and Tech

The order we build things, what each piece does, and what you should be able to explain. Routes and field names: `06-api-contract.md` (tiebreaker if anything here disagrees).

## Setup: 3 laptops, 1 hotspot
```
Laptop A                      Laptop B                         Laptop C
victim/ + agent/   --HTTP-->  witness/ + dashboard/   <--HTTP--  feed/ + attacks/
(the "bank",                  (the judge, shows                (settlement side
 attacker's machine)           SOC + auditor tabs)               + red team, mock anchor file)
            shared/ (one copy in the repo, imported by agent/ and witness/)
```
- Folders: `shared/`, `victim/`, `agent/`, `witness/`, `feed/`, `dashboard/`, `attacks/`, `tests/`.
- All talk over HTTP on the hotspot. `WITNESS_URL` env var on every laptop (write the IP on a sticky note at 8:00).
- Agent and feed **poll** the witness; only Laptop B needs an inbound firewall rule.
- No cloud services. The external anchor is a mock: Laptop C pulls `GET /anchor/latest` and appends it to a local file.

---

## Timeline
| Time | Build | Ready for |
|---|---|---|
| 8:00 to 8:30 | Step 0: setup | |
| 8:30 to 11:00 | Steps 1 to 3 | |
| 11:00 to 1:00 | Steps 4 to 5 | |
| 1:00 to 2:00 | Step 6 (dashboard, real data) | |
| 2:00 to 3:00 | **Freeze, rehearse** | **Round 1, 3 PM** |
| 4:00 to 6:30 | Steps 7 to 9 | |
| 6:30 to 7:30 | **Freeze, rehearse** (pick full or fallback demo by 6:30) | **Round 2, 7:30 PM** |
| 8:30 PM to 2:00 AM | Steps 10 to 13 | |
| 2:00 to 6:00 AM | Sleep in shifts, polish | |
| 6:00 to 8:00 AM | **Freeze**, full test suite, backup video | |
| 8:00 to 10:00 AM | Rehearse twice, final slides | **Final, 10 AM** |

Jaganath builds the dashboard with **fake data** from 8:30, so Round 1 already looks like a product. It switches to real data in Step 6.

---

## Steps

### Step 0 · Setup + registration (all)
Repo, folders, `AGENTS.md`, `CLAUDE.md`, IPs noted, ping test between laptops.

**Registration:** at startup, before sending anything else, the agent calls `POST /register/agent` and the feed calls `POST /register/feed`. Each gets back a `key_id`. The witness refuses entries, heartbeats and confirmations from any key it hasn't registered.

### Step 1 · Entry format + canonical encoding (Jeev, `shared/`)
**What:** one shared definition of a log entry, in `shared/`, imported by `agent/` and `witness/`. Never copied into either.

Fields: `seq`, `timestamp`, `event_type`, `txn_id`, `from_account`, `to_account`, `amount_paise`, `from_balance_paise`, `to_balance_paise`, `prev_hash`, `key_id`, `hash`, `signature`.

- `hash` = SHA-256 over the canonical encoding of every field except `hash` and `signature`.
- `signature` = Ed25519 over the canonical encoding of every field except `signature`.
- All hashes, keys and signatures are base64.
- `GENESIS_PREV_HASH = base64.b64encode(b"\x00" * 32)` = `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`. The entry with `seq = 0` uses it as `prev_hash`.

**Tech:** "canonical encoding" means turning an entry into bytes the exact same way every time: keys sorted, no extra spaces, integers only. If two machines encode the same entry differently, the hash differs and you get a false alarm.

**Explain it:** Why do floats break this? Why must keys be sorted?

### Step 2 · Fake bank (Jaganath, `victim/`)
**What:** SQLite with an `accounts` table (balances) and a `transactions` table. A loop that creates random transfers every second.

**Fast mode:** `--fast` (or `FAST_MODE=1`) creates transfers as fast as possible. Used only for the T0 clean-run test (10,000 transactions in minutes). Normal 1/sec pace stays for live demos.

**Tech:** each transfer subtracts from one account and adds to another in the same database transaction, so money is never created or lost.

**Explain it:** Where does the "real" balance live?

### Step 3 · Agent: chain + sign + send (Jeev, `agent/`)
**What:** reads each new transaction, builds an entry (including `from_balance_paise` / `to_balance_paise` as read from the bank DB), signs it, POSTs it to `/entries`. Sends a signed heartbeat every 5 seconds.

**Local copy:** the agent also stores every entry it builds in its own local SQLite (`agent/`). This is the copy A3/A7 tamper with and `attacks/compare_local.py` sends to `POST /verify/compare`.

**Tech:**
- **Hash chain:** each entry stores the hash of the previous one. Changing any old entry changes its hash, which no longer matches the next entry's `prev_hash`. One edit breaks everything after it.
- **Sequence number:** counts up by 1. A missing number = something was deleted.
- **Ed25519 signature:** the agent signs with a private key. Anyone with the public key can check it, but only the private key can create it. The witness only ever gets the public key.
- **No balance logic in the agent.** It reports what the bank DB says; the witness decides.

**Fallback:** if sending fails, keep entries in a local queue and retry with the same `seq`.

**Explain it:** Why can't the witness forge an entry?

### Step 4 · Witness: verify + store + silence alert + self-check (Jeev, `witness/`)
**What:** FastAPI server. On every entry, check against the last **accepted** entry (`last_good_seq` / `last_good_hash`):
- `key_id` is registered (else `unknown_key_id`), signature valid
- `prev_hash` = `last_good_hash`, `seq` = `last_good_seq + 1`
- `timestamp` is later than the last accepted entry's timestamp (monotonic). **Not** "close to now": queued retries arrive late and must not alert.

Accepted entries advance `last_good_*`. A rejected entry is stored as evidence and raises exactly one alert, but never becomes what the next entry is checked against, so one attack doesn't cascade.

**Silence:** a background task checks the last valid heartbeat. A heartbeat only counts if its signature is valid and its timestamp is later than the previous heartbeat (no replays). More than 15 s without one = silence alert (agent killed or blocked).

**Periodic self-check (every 5 s):** re-reads the stored **accepted** entries, recomputes each `hash` from its fields via `shared/`, and checks `prev_hash` links and `seq` continuity. A mismatch = someone edited the witness DB directly (A1, A2): Layer 1 red within 5 s, no new entry needed. One alert per broken entry, not one every 5 s.

**`GET /verify?from_seq&to_seq`** exists from this step as a raw endpoint (Step 12 is just its UI). **`POST /verify/compare`** takes the agent's local entries and reports what's missing or different (T2d, A3, A7).

**Explain it:** Which check catches a deleted entry? Which catches a killed agent? Why validate against the last *accepted* entry?

### Step 5 · Witness: balance replay, Check 1 (Jeev, `witness/`)
**What:** witness keeps its own dictionary `account -> balance`, updated from each accepted entry. Compares with the agent's `from_balance_paise` and `to_balance_paise`, and alerts on the specific account that's wrong.

**Tech:** the witness never trusts the agent's numbers. They're claims. The witness's own replay is the truth.

**Explain it:** Why is a balance computed on the bank's machine useless against a root attacker?

### Step 6 · Dashboard on real data (Jaganath, `dashboard/`)
**What:** SOC tab reads from witness API (`/status`, `/alerts`): Layer 1 status, Layer 2 status, Layer 3 status, alert list with the exact entry that broke.

**Fallback:** if real data isn't ready by 2:00, demo with fake data mode and say so.

**➡ Round 1 is here.**

### Step 7 · State challenge, Check 2 (Jeev + Jaganath)
**What:** witness picks a random account at a random time and asks the agent (via `GET /challenge/poll`) "what's its balance in the DB right now, and up to which seq?" Agent replies on `POST /challenge/response`. Witness compares with its replay at that seq.

**Tech:** catches someone editing the database directly without any log entry. The chain stays green; this goes red. **This is our headline demo.**

**Explain it:** Why include `last_seq` in the answer?

### Step 8 · Confirmation feed, Check 3 (3rd member `feed/`, Jeev wires matching)
**What:** a separate program on Laptop C with its **own key**. For every real transfer, it sends its own signed confirmation to `POST /feed/confirmations`. Witness matches by `txn_id`, accounts and amount, 30 seconds either side.

**Tech:** the feed stands in for the settlement system / other bank. A transaction with no confirmation = fake. A confirmation with no transaction = hidden.

**Demo simplification:** the bank tells the feed about each real transfer over a side channel. A root attacker controlling that channel could lie to the feed too; in production the feed is a separate organisation's system with no channel from the platform. Say this in the pitch (`03-pitch-demo.md`). For A13/A14, run the fake transfer through the agent only, never the side channel.

**Explain it:** Why does the feed need its own key and its own laptop?

### Step 9 · Conservation, Check 4 (Jeev)
**What:** total money in all accounts must equal starting total plus confirmed inflows minus confirmed outflows.

**➡ Round 2 is here.**

### Step 10 · Key rotation (Jeev)
Every N entries: new key pair, `POST /keys/rotate` signed with the old private key, then delete the old private key. The witness adds the new `key_id` with `effective_from_seq`; old `key_id`s stay valid only for entries before that seq. A stolen key can't forge the past.

### Step 11 · Signed receipts + mock anchor (Jeev)
Witness signs "got entry #N with hash X at time T" and returns it in the `/entries` response; the agent keeps receipts. Every few minutes the witness publishes the latest chain head on `GET /anchor/latest`; Laptop C polls it and appends to its anchor file.

### Step 12 · Auditor tab + export (Jaganath)
UI on top of `GET /verify` and `GET /export`: verify a range of entries, show reconciliation results, export a report (HTML or PDF).

### Step 13 · Random challenges (Jeev)
Hash challenges (`type: hash`) at random times, replacing fixed-interval checks. No reply within 5 s = missed-challenge alert.

**Only if all above are stable:** login + roles, system events (logins, agent stopped).

**➡ Final is here.**

---

## Slide-only (we explain, don't build)
Multi-platform profiles (and profile-hash checks, A8), multiple witnesses, real blockchain/timestamp anchor, TPM, mutual TLS, MFA, Docker deployment.
