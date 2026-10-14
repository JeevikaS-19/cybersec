# 02 · Build Flow and Tech (v3)

The order we build things, what each piece does, and what you should be able to explain.
Design: `LAYERS_PLAN.md`. Routes and fields: `06-api-contract.md` (tiebreaker if anything here disagrees).

**Naming used everywhere:**
- **Checks** (detect, the minimal base): **Check A** sealed chain · **Check B** outside witness (heartbeat + challenges) · **Check C** truth check (balance replay + state challenge).
- **Layers** (respond, v3): **Layer 1** command tripwire · **Layer 2** heartbeat/checksum hooks · **Layer 3** break glass.
- **Vault + evidence bundles**: the shared piece every layer uses.

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

## Folders and owners (proposed, confirm at 8:00)
| Folder | What | Owner |
|---|---|---|
| `shared/` | canonical encoding, hashing, signing | Jeev |
| `agent/` | chain + sign + send, heartbeat, challenge replies (runs in log-server) | Jeev |
| `witness/` | verify, store, Checks A to C, layer events, break-glass relay | Jeev |
| `layers/common/` | `events.py`, `evidence.py` (bundles + vault) | Jeev |
| `layers/l2_hooks/`, `layers/l3_breakglass/` | Layer 2 and 3 | Jeev |
| `layers/l1_tripwire/` | wrappers, `coc-*` commands, `audit.rules`, `coc-unlock` | 3rd member |
| `victim/` | fake bank app writing logs + SQLite (runs in log-server) | Jaganath |
| `dashboard/` | SOC + auditor views | Jaganath |
| `docker/` | compose file, Dockerfiles, MinIO init | Jaganath |
| `attacks/`, `docs/demo_script.md` | attack scripts, demo | 3rd member |
| `config/layers.yaml` | on/off switch per layer and check | Jeev |
| `tests/` | self-tests (Claude Code writes and runs) | all |

---

## Timeline
| Time | Build | Ready for |
|---|---|---|
| 8:00 to 8:30 | Step 0 setup, Step 1 Phase 0 spike | |
| 8:30 to 11:00 | Steps 2 to 3 (compose up, base Checks A and B) | |
| 11:00 to 1:00 | Steps 4 to 5 (Check C, vault + evidence) | |
| 1:00 to 2:00 | Step 6 (Layer 1 wrappers), dashboard on real data | |
| 2:00 to 3:00 | **Freeze, rehearse** | **Round 1, 3 PM** |
| 4:00 to 6:30 | Steps 7 to 8 (auditd backstop, Layer 2) | |
| 6:30 to 7:30 | **Freeze, rehearse** | **Round 2, 7:30 PM** |
| 8:30 PM to 2:00 AM | Steps 9 to 10 (Layer 3, dashboard additions) | |
| 2:00 to 6:00 AM | Sleep in shifts, Step 11 demo script, polish | |
| 6:00 to 8:00 AM | **Freeze**, full test suite, backup video | |
| 8:00 to 10:00 AM | Rehearse twice, final slides | **Final, 10 AM** |

Jaganath builds the dashboard with **fake data** from 8:30, so Round 1 already looks like a product. Steps 0 to 6 alone are a working story if time runs short.

---

## Steps

### Step 0 · Setup (all)
Repo pulled, `docker compose version` works, base images already pulled (done before the event). Ownership table above confirmed.

### Step 1 · Phase 0 kernel spike (Jeev, 30 min max)
Script inside `log-server` that checks: auditd rules (`CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`), fanotify (`CAP_SYS_ADMIN`), `chattr +a/+i` on the mounted log volume (`CAP_LINUX_IMMUTABLE`), iptables (`CAP_NET_ADMIN`). Write results to `docs/phase0_results.md`. Anything that fails uses its fallback (inotify, read-only remount) and goes on the honest-limits slide.

**Explain it:** Why can only one auditd own the audit subsystem? Why mount logs as a volume?

### Step 2 · Docker compose skeleton (Jaganath, `docker/`)
Five containers start with one command. `witness` image has no `openssh-server`. `vault` = MinIO with object lock, compliance mode, 1-day retention, a PutObject-only credential for log-server and a read-only auditor credential.

### Step 3 · Base: Checks A and B (Jeev, `shared/`, `agent/`, `witness/`)
**Registration:** at startup the agent calls `POST /register/agent`, gets a `key_id`.

**Entry format** (in `shared/`, imported by agent and witness, never copied): `seq`, `timestamp`, `event_type`, `txn_id`, `from_account`, `to_account`, `amount_paise`, `from_balance_paise`, `to_balance_paise`, `prev_hash`, `key_id`, `hash`, `signature`. Canonical encoding: sorted keys, no spaces, integers only. Base64 for hashes, keys, signatures. `GENESIS_PREV_HASH = base64(32 zero bytes)`.

**Agent:** reads each new `victim/` transaction, builds the entry, signs it, POSTs `/entries`, keeps a local SQLite copy, queues and retries with the same `seq` if sending fails. Signed heartbeat every 5 s. No balance logic.

**Witness:** validates each entry against the last **accepted** entry (signature, `prev_hash`, `seq`, monotonic timestamp). Rejected entries are stored and alert once, never cascade. Silence alert after 15 s with no valid heartbeat. Self-check every 5 s re-hashes stored entries (live Check A red on a direct DB edit). `GET /verify` for range checks.

**Explain it:** Why can't the witness forge an entry? Why check against the last *accepted* entry?

### Step 4 · Base: Check C (Jeev, `witness/`)
Witness keeps its own `account -> balance` replay and compares with `from_balance_paise` / `to_balance_paise`. **State challenge** at random times: "what's the balance of account X and up to which seq?" The agent answers from the bank DB. Catches a direct DB edit with no log entry while Checks A and B stay green.

**Explain it:** Why is a balance computed on the bank's machine useless against a root attacker?

### Step 5 · Vault + evidence bundles (Jeev, `layers/common/`)
- `events.py`: one internal event format (`layer`, `trigger`, `time`, `who`, `detail`).
- Continuous streaming: every log entry pushed to the vault as written (the "before" copy).
- `evidence.py`: builds a bundle when anything fires (layer, trigger, who: `auid`/uid/process/exe/source IP, log snapshot + hashes, diff vs vault "before", auditd records), signs it with the agent key, pushes it to the vault, sends the bundle hash to the witness (`POST /events`).
- `TODO` stub (do not build): local encrypted buffer for when the network is cut before a push.

**Explain it:** Why can't even the vault admin delete a locked object? Why send the bundle hash to the witness?

### Step 6 · Layer 1 wrappers (3rd member, `layers/l1_tripwire/`)
Wrapper dir first in `PATH` (`/opt/trip/bin`): `nano`, `vi`, `vim`, `gedit`, `rm`, `mv`, `cp`, `sed`, `truncate`, `shred`, `cat` on log paths; `cd` via a shell function in the system profile. Each wrapper emits a Layer 1 event, triggers a bundle, alerts, and **blocks** the command. Team commands: `coc-view`, `coc-status`, `coc-verify`. `coc-unlock` checks a key against a stored hash and restores originals for that session only, logged.

**➡ Round 1 is here** (Checks A to C + Layer 1 wrappers + vault).

### Step 7 · Layer 1 backstop: auditd (Jeev + 3rd member)
`audit.rules`: execve rules for the real binaries (full-path use still caught), `-p wa` watches on the log **directory** (temp-file + rename saves caught). Wrappers are detection; auditd is the real enforcement. **Fallback** if Phase 0 failed: inotify on the log dir + process lookup.

### Step 8 · Layer 2 hooks (Jeev, `layers/l2_hooks/`)
Do not rewrite Checks A or B; connect them. Check A mismatch, failed challenge or missed heartbeat → Layer 2 event → bundle with "after" version, diff vs vault "before", auditd records (who + which program). Layer 1's auditd file-write events feed the same check, so a direct edit is flagged immediately. Config decides which Layer 2 events escalate to Layer 3 (default: repeated failures, or any failure during an admin lockout).

**➡ Round 2 is here.**

### Step 9 · Layer 3 break glass (Jeev, `layers/l3_breakglass/`)
**Triggers:** changes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers(.d)`, admin `authorized_keys`, admin locked or removed from sudo; Layer 2 escalation; SOC panic button.
**Response, in this exact order, never reboot:** 1 capture (processes, `ss -tnp`, sessions, auditd, log hashes) → 2 push final bundle, hash to witness → 3 isolate (iptables DROP except vault + witness) → 4 freeze (`chattr +i` or read-only remount, stop writers) → 5 lock out (lock interactive accounts, kill sessions) → 6 report FROZEN.
**Unlock:** Shamir 2-of-3 (`pycryptodome`), holders auditor / SOC lead / legal. Log server stores only a hash of the secret. Shares go into the dashboard, never the frozen server; the witness sends a signed unlock; the log server verifies and reverses 5, 4, 3, logging the unlock.

### Step 10 · Dashboard additions (Jaganath, `dashboard/`)
SOC: live timeline color-coded by layer, state normal / alert / FROZEN, panic button. Auditor: bundle list with verification status (signature valid, hash matches witness), before / after / diff / who per incident, unlock panel (enter shares).

### Step 11 · Demo script + full run (3rd member, `docs/demo_script.md`)
Follow `03-pitch-demo.md` Final demo order. Write `docs/integration_map.md` (where heartbeat, checksum, keys, dashboard live and which functions the layers call) for the pitch Q&A.

**➡ Final is here.**

---

## Slide-only (we explain, don't build)
Settlement confirmation feed, conservation check, key rotation, signed receipts + external anchor, multi-witness, profiles, TPM, mutual TLS, MFA, local encrypted buffer for network cuts.
