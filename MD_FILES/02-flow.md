# 02 · Build Flow and Tech (v3)

The order we build things, what each piece does, and what you should be able to explain.
Design: `LAYERS_PLAN.md`. Routes and fields: `06-api-contract.md` (tiebreaker if anything here disagrees).

**Build order: Layer 2 -> Layer 1 -> Layer 3.**
- **Layer 2 · heartbeat + checksum** (detect, and say *what kind* of tampering): **Check A** sealed chain (checksums), **Check B** outside witness (heartbeat + challenges), **Check C** truth check (balance replay + state challenge), plus the **tamper classifier**, the vault and evidence bundles.
- **Layer 1 · command tripwire** (catch the intruder in the act): wrappers + `coc-*` commands, auditd backstop feeding Layer 2.
- **Layer 3 · break glass** (last resort): freeze everything, 2-of-3 unlock.

## Setup: Docker on one laptop
Docker Desktop on Windows (WSL2 backend). One `docker compose up` runs the whole demo.
```
attacker  --(stolen admin creds)-->  log-server  --HTTP-->  witness  <--HTTP--  dashboard
                                     victim/ + agent/        (API port only,     (SOC + auditor)
                                     + layers/               no sshd)
                                          |                                         |
                                          +--PutObject only-->  vault (MinIO)  <--read only--+
```
- Containers: `log-server`, `witness`, `vault`, `dashboard`, `attacker`. Containers reach each other by name (`http://witness:8000`).
- `log-server` polls the witness; the witness never calls out. Only the witness API port and the dashboard port are published.
- No cloud services. Laptop hotspot is only for AI tools.

## Folders and owners (proposed, confirm after Round 1)
| Folder | What | Owner |
|---|---|---|
| `shared/` | canonical encoding, hashing, signing | Jeev |
| `agent/` | chain + sign + send, heartbeat, challenge replies (runs in log-server) | Jeev |
| `witness/` | verify, store, Checks A to C, layer events, break-glass relay | Jeev |
| `layers/common/` | `events.py`, `evidence.py` (bundles + vault) | Jeev |
| `layers/l2_hooks/`, `layers/l3_breakglass/` | Layer 2 and 3 | Jeev |
| `layers/l1_tripwire/` | wrappers, `coc-*` commands, `audit.rules`, `coc-unlock` | 3rd member |
| `victim/` | fake bank app writing logs + SQLite (runs in log-server) | Jeev writes the stub (Step 1), Jaganath extends after Round 1 |
| `dashboard/` | SOC + auditor views | Jaganath |
| `docker/` | compose file, Dockerfiles, MinIO init | Jaganath |
| `attacks/`, `docs/demo_script.md` | attack scripts, demo | 3rd member |
| `config/layers.yaml` | on/off switch per layer and check | Jeev |
| `tests/` | self-tests (Claude Code writes and runs) | all |

---

## Before Round 1: work independently, no Docker
Until the 3 PM round everyone works on their own, with no shared setup:
- **Jeev:** Layer 2 (Steps 0 to 5), running natively on the laptop as plain Python processes: fake bank, agent, witness. `WITNESS_URL=http://127.0.0.1:8000`.
- **3rd member:** Phase 0 spike (side task below) and attack scripts for Layer 2 (A4 to A7, `07-attacks.md`), run against Jeev's local processes.
- **Jaganath:** nothing in the build path until after Round 1. Docker, the dashboard and the full bank app start at 4 PM (Step 6). Optional before then: Round 1 slides.

Round 1 shows alerts in a terminal watcher (Step 5) instead of the dashboard.

## Timeline
| Time | Build | Ready for |
|---|---|---|
| 8:00 to 8:30 | Step 0 setup | |
| 8:30 to 9:00 | Step 1 fake bank stub | |
| 9:00 to 11:30 | Step 2 Checks A + B (2a shared, 2b agent, 2c witness) | |
| 11:30 to 12:30 | Step 3 Check C | |
| 12:30 to 1:30 | Step 4 tamper classifier | |
| 1:30 to 2:00 | Step 5 terminal alert watcher | |
| 2:00 to 3:00 | **Freeze, rehearse** | **Round 1, 3 PM: Layer 2** |
| 4:00 to 5:00 | Step 6 Docker + dashboard (Jaganath joins) | |
| 5:00 to 6:30 | Step 7 vault + evidence, Step 8 Layer 1 wrappers | |
| 6:30 to 7:30 | **Freeze, rehearse** (Step 9 auditd only if already working) | **Round 2, 7:30 PM: Layers 2 + 1** |
| 8:30 PM to 2:00 AM | Step 9 auditd backstop (if not done), Steps 10 to 11 (Layer 3, dashboard additions) | |
| 2:00 to 6:00 AM | Sleep in shifts, Step 12 demo script, polish | |
| 6:00 to 8:00 AM | **Freeze**, full test suite, backup video | |
| 8:00 to 10:00 AM | Rehearse twice, final slides | **Final, 10 AM: all three** |

---

## Steps

### Step 0 · Setup (Jeev)
Python venv, `pip install fastapi uvicorn requests cryptography pyyaml pytest ruff`, `requirements.txt`. Empty folders with `__init__.py`: `shared/`, `victim/`, `agent/`, `witness/`, `tests/`. `config/layers.yaml` with every check and layer switched on. Native only; no Docker yet.

### Step 1 · Fake bank stub (Jeev, `victim/`, Jaganath extends after Round 1)
`victim/bank.py`: SQLite `bank.db` with `accounts` (balances, integer paise) and `transactions`. A loop creating one random transfer per second, debit and credit in the same DB transaction. `--fast` creates them as fast as possible (T0 only). Keep it under ~60 lines.

**Explain it:** Where does the "real" balance live?

---

## Layer 2 · Heartbeat + checksum

### Step 2 · Checks A and B (Jeev)
**2a · `shared/`** (written once, then frozen): entry fields `seq`, `timestamp`, `event_type`, `txn_id`, `from_account`, `to_account`, `amount_paise`, `from_balance_paise`, `to_balance_paise`, `prev_hash`, `key_id`, `hash`, `signature`. Canonical encoding (sorted keys, no spaces, integers only), SHA-256, Ed25519 sign/verify, base64 helpers, `GENESIS_PREV_HASH = base64(32 zero bytes)`. Tests T1a.

**2b · `agent/`:** registers (`POST /register/agent`, gets `key_id`), reads each new `bank.db` transaction, builds the entry, signs it, POSTs `/entries`, keeps a local SQLite copy, queues and retries with the same `seq` if sending fails. Signed heartbeat every 5 s. Answers hash challenges. No balance logic.

**2c · `witness/`:** FastAPI. Validates each entry against the last **accepted** entry (signature, `prev_hash`, `seq`, monotonic timestamp). Rejected entries are stored and alert once, never cascade. Silence alert after 15 s with no valid heartbeat. Random hash challenges. Self-check every 5 s re-hashes stored entries (Check A red live on a direct DB edit). `GET /status`, `GET /alerts`, `GET /verify`.

**Explain it:** Why can't the witness forge an entry? Why check against the last *accepted* entry?

### Step 3 · Check C (Jeev, `witness/` + small agent hook)
Witness keeps its own `account -> balance` replay and compares with `from_balance_paise` / `to_balance_paise`. **State challenge** at random times: "what's the balance of account X and up to which seq?" The agent answers from `bank.db`. Catches a direct DB edit with no log entry while Checks A and B stay green.

**Explain it:** Why is a balance computed on the bank's machine useless against a root attacker?

### Step 4 · Tamper classifier (Jeev, `witness/classify.py`)
Every alert carries a `tamper_type` (list in `06-api-contract.md`), so the SOC sees **what kind** of tampering happened:

| Signal | `tamper_type` |
|---|---|
| stored entry's hash no longer matches its fields | `entry_edited` |
| `seq` gap / missing row | `entry_deleted` |
| `seq` out of order, links swapped | `entries_reordered` |
| duplicate `seq` / same entry twice | `entry_replayed` |
| extra entry whose link doesn't fit and isn't a gap | `entry_inserted` |
| timestamp earlier than last accepted | `backdated` |
| bad signature / unknown `key_id` | `forged` |
| no valid heartbeat / missed challenge | `agent_silenced` |
| reported balance differs from witness replay | `balance_misreported` |
| state challenge mismatch, chain green | `db_edited_without_log` |

For `entry_edited`, once Step 7 (vault) exists, also name **which field** changed and old -> new value.

**Explain it:** Why does the type of tampering matter to a SOC analyst or an auditor?

### Step 5 · Terminal alert watcher (Jeev, `witness/watch.py`)
Polls `GET /status` and `GET /alerts` every second and prints Checks A to C as green/red plus each new alert with its `tamper_type`, in color. This is the Round 1 demo screen until the dashboard exists. Under ~50 lines.

**Round 1 is here** (Layer 2: detects tampering and names what kind).

### Side task · Phase 0 kernel spike (3rd member, before 4 PM, 30 min max)
`docker run` a Debian container with the needed capabilities and check: auditd rules (`CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`), fanotify (`CAP_SYS_ADMIN`), `chattr +a/+i` on a mounted volume (`CAP_LINUX_IMMUTABLE`), iptables (`CAP_NET_ADMIN`). Results in `docs/phase0_results.md`. Failures use their fallback (inotify, read-only remount) and go on the honest-limits slide. Layers 1 and 3 depend on this; Layer 2 does not.

---

## After Round 1: Docker and the vault

### Step 6 · Docker compose + dashboard (Jaganath)
Five containers start with one command: `log-server` (bank + agent + layers), `witness` (no `openssh-server`, API port only), `vault` (MinIO, object lock, compliance mode, 1-day retention, PutObject-only log-server credential, read-only auditor credential), `dashboard`, `attacker`. Move Jeev's native processes into the containers; `WITNESS_URL=http://witness:8000`. Dashboard SOC view on real data (`/status`, `/alerts`).

### Step 7 · Vault + evidence bundles (Jeev, `layers/common/`)
- `events.py`: one internal event format (`layer`, `trigger`, `tamper_type`, `time`, `who`, `detail`).
- Continuous streaming: every log entry pushed to the vault as written (the "before" copy).
- `evidence.py`: on every Layer 2 alert, builds a bundle (layer, trigger, tamper type, who, log snapshot + hashes, diff vs vault "before", auditd records once Step 9 exists), signs it with the agent key, pushes it to the vault, sends the bundle hash to the witness (`POST /events`).
- `TODO` stub (do not build): local encrypted buffer for when the network is cut before a push.

**Explain it:** Why can't even the vault admin delete a locked object? Why send the bundle hash to the witness?

---

## Layer 1 · Command tripwire

### Step 8 · Wrappers + team commands (3rd member, `layers/l1_tripwire/`)
Wrapper dir first in `PATH` (`/opt/trip/bin`): `nano`, `vi`, `vim`, `gedit`, `rm`, `mv`, `cp`, `sed`, `truncate`, `shred`, `cat` on log paths; `cd` via a shell function in the system profile. Editors always trip; file commands trip only on log paths, so normal work elsewhere is untouched. Each wrapper emits a Layer 1 event and alerts. **Deception mode** (default, `config/layers.yaml` → `layer1.mode`): editors open a decoy copy, so the real log is never touched; on save, the attempted diff goes to the witness as evidence. `rm`/`mv`/`cp`/`sed`/`truncate`/`shred` on a log report success and change nothing; `cat` shows the log (reading is harmless). `block` mode refuses instead. Events go through a spool (`/var/spool/coc`, write-only for users): wrappers never hold the agent key, the agent signs and sends them (`POST /events`). Built in `layers/l1_tripwire/` (`trip.py`, `coc.py`, `install.sh`, `smoke.sh`) and `layers/common/events.py`. Team commands: `coc-view`, `coc-status`, `coc-verify`. `coc-unlock` checks a key against a stored hash and restores originals for that session only, logged.

### Step 9 · auditd backstop feeding Layer 2 (Jeev + 3rd member)
`audit.rules`: execve rules for the real binaries (full-path use still caught), `-p wa` watches on the log **directory** (temp-file + rename saves caught). Wrappers are detection; auditd is the real enforcement. **Fallback** if Phase 0 failed: inotify on the log dir + process lookup.
auditd file-write events feed Layer 2, so a direct edit is flagged immediately and the bundle names **who** (`auid`, uid, process, exe). Config decides which Layer 2 events escalate to Layer 3 (default: repeated failures, or any failure during an admin lockout).

**Round 2 is here** (Layers 2 + 1).

---

## Layer 3 · Break glass

### Step 10 · Break glass (Jeev, `layers/l3_breakglass/`)
**Triggers:** changes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers(.d)`, admin `authorized_keys`, admin locked or removed from sudo; Layer 2 escalation; SOC panic button.
**Response, in this exact order, never reboot:** 1 capture (processes, `ss -tnp`, sessions, auditd, log hashes) -> 2 push final bundle, hash to witness -> 3 isolate (iptables DROP except vault + witness) -> 4 freeze (`chattr +i` or read-only remount, stop writers) -> 5 lock out (lock interactive accounts, kill sessions) -> 6 report FROZEN.
**Unlock:** Shamir 2-of-3 (`pycryptodome`), holders auditor / SOC lead / legal. Log server stores only a hash of the secret. Shares go into the dashboard, never the frozen server; the witness sends a signed unlock; the log server verifies and reverses 5, 4, 3, logging the unlock.

### Step 11 · Dashboard additions (Jaganath, `dashboard/`)
SOC: live timeline color-coded by layer, tamper type on every alert, state normal / alert / FROZEN, panic button. Auditor: bundle list with verification status (signature valid, hash matches witness), before / after / diff / who per incident, unlock panel (enter shares).

### Step 12 · Demo script + full run (3rd member, `docs/demo_script.md`)
Follow `03-pitch-demo.md` Final demo order. Write `docs/integration_map.md` (where heartbeat, checksum, keys, dashboard live and which functions the layers call) for the pitch Q&A.

**Final is here.**

---

## Slide-only (we explain, don't build)
Settlement confirmation feed, conservation check, key rotation, signed receipts + external anchor, multi-witness, profiles, TPM, mutual TLS, MFA, local encrypted buffer for network cuts.
