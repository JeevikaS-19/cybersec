# 08 · Fixes applied (changelog against the pack you flagged)

1. **No API contract** → `06-api-contract.md` added. Agent and feed poll the witness (no inbound rule needed on Laptops A/C). Used by `02-flow.md` and `07-attacks.md`.
2. **Ambiguous `running_balance_paise`** → split into `from_balance_paise` and `to_balance_paise` everywhere (shared encoding, entries, Check 1 replay, T3a).
3. **No `shared/` folder** → added, owned by Jeev, holds canonical encoding/hashing, imported by `agent/` and `witness/`. Written in Step 1.
4. **No registration step** → `POST /register/agent` and `POST /register/feed` defined in `06-api-contract.md`, called at agent/feed startup in Step 0; witness refuses unregistered keys.
5. **Retries vs. timestamp check clash** → Step 4's check changed from "close to wall-clock now" to "monotonically later than the previous stored entry." Freshness/liveness is the separate heartbeat-silence check. `06-api-contract.md`'s `non_monotonic_timestamp` reason documents this. T2b and T2c in `05-self-tests.md` updated to test this directly.
6. **T0 would take 2.8 hours** → fast mode added to the bank generator (Step 2), used only for T0; normal 1/sec mode kept for live demos.
7. **T2d had nothing to run against** → witness's `GET /verify` endpoint moved up to be available from Step 4 (core logic), with the Step 12 auditor tab as just its UI. `attacks/` and self-tests use it directly from Step 4 on.
8. **Feed demo shortcut undercuts "settlement never confirmed it"** → named explicitly as a demo simplification in `02-flow.md` Step 8, `03-pitch-demo.md`'s honest-limits slide, and a rehearsed judge question. `07-attacks.md` notes A13/A14 must bypass the shortcut to demo the real mechanism.
9. **pytest/ruff allowed?** → confirmed, added to the allowed list in `01-rules.md` explicitly as dev-only tools.
10. **05 referenced attacks with no list** → `07-attacks.md` created; `05-self-tests.md`'s handover table now points to it.

---

## v3 switch (LAYERS_PLAN.md)
- v3 replaces the v2 build. The v2 checks stay as a minimal base, renamed **Check A** (sealed chain), **Check B** (outside witness), **Check C** (truth check). v3 owns **Layers 1 to 3** (tripwire, hooks, break glass).
- Setup moved from 3 laptops on a hotspot to Docker on one laptop (`log-server`, `witness`, `vault`, `dashboard`, `attacker`).
- Antigravity still builds and Claude Code reviews; LAYERS_PLAN's "Claude Code" instructions apply to the builder.
- Dropped to slide-only: settlement feed (old Check 3), conservation check, key rotation, signed receipts, external anchor, `/verify/compare`.
- Rewritten: `00`, `01`, `02`, `03`, `05`, `06`, `07`. Updated: `04`, `LAYERS_PLAN.md` header and ground rules. New routes: `/events`, `/timeline`, `/breakglass/*`; `/status` now reports `checks`, `layers` and `state`.
- Allowed libraries added: pycryptodome (Shamir), minio, pyyaml.

## Build order: Layer 2 → Layer 1 → Layer 3
- Layer 2 is now the heartbeat + checksum layer itself (Checks A to C), plus a tamper classifier: every alert carries a `tamper_type`. Built first, demoed in Round 1.
- Layer 1 (tripwire + auditd backstop) in Round 2; Layer 3 (break glass) for the Final.
- Updated `01`, `02`, `03`, `05`, `06`, `07`, `LAYERS_PLAN.md`.

## Independent work until Round 1
- Jaganath's work (Docker, dashboard, full bank app) moves after the 3 PM round (Step 6).
- Steps renumbered: 0 setup, 1 fake bank stub, 2 Checks A + B (2a shared, 2b agent, 2c witness), 3 Check C, 4 classifier, 5 terminal watcher, then 6 Docker, 7 vault, 8 to 9 Layer 1, 10 Layer 3, 11 dashboard additions, 12 demo. Phase 0 is a side task for the 3rd member.
- Layer 2 runs natively (no Docker) before Round 1; Round 1 demo uses the terminal watcher.

## Layer 1 build
- Deception mode added (default): decoy editor, real log untouched, attempted diff captured as evidence. `block` mode kept as a switch.
- Events path: producers write to a spool, the agent signs and sends `POST /events`; wrappers never hold the agent key. `/events` gains a `detail` field.
- File commands trip only on log paths; editors always trip.
- Team access changed: `coc-*` commands and the revert key are gone. The team uses `<cmd> --<profile-id>` (per-platform secret, scrypt hash only); guarded commands and paths come from config.

## Layer 3 build
- Break glass replaced by quarantine: trigger = 45 s without the witness (network cut). Capture → seal → site down → lock out everyone incl. root → QUARANTINED; never reboot.
- Unlock = 2 of 3 key-holder approvals on the auditor view → witness-signed command for that quarantine id. Shamir is the production path.
- Routes: `/quarantine/report|approve|poll` replace `/breakglass/*`.
- Agent keeps sealing locally while the network is cut.

## Platform adapter (P1)
- `config/platform.yaml` + `agent/source.py`: the agent latches onto any SQLite/PostgreSQL bank by mapping table/column names and units (paise or DECIMAL rupees). Example for the team's bank: `config/platform.team-bank.yaml` (read-only DB user, DSN from env).
- Entries gain `txn_time` (platform time); `timestamp` is now the sealing time, so out-of-order commits never look backdated. Record checks compare `txn_time`.
- Rows committing out of id order: skipped ids are re-checked for `gap_seconds`; rolled-back ids are dropped. A `sealed_rows` table prevents double-sealing.
- Deposits/withdrawals: missing side = `"external"`. Platforms without stored balances: Check C seeds each account from its first state challenge.
- State challenges read balance + unseen rows from one database snapshot (REPEATABLE READ), so a commit mid-question can't cause a false alarm.
- Verified: busy PostgreSQL 16 bank (4 concurrent writers, 27 rollbacks) -> 152/152 rows verified, zero false alarms; row edit and balance edit caught within 5 s.

## Layer 1 backstop (P3)
- auditd is not available inside Docker Desktop containers (audit is host-only), so the backstop is the planned fallback: inotify on the protected folders + /proc attribution (user, login uid, program, source IP), root-owned.
- Authorized edits leave a marker encrypted to the backstop's X25519 key (proves the profile-id, never stores it in plain text, can't be forged without it). The wrapper then exec()s the real command, so the profile-id is no longer visible in `ps`.
- Platform writers are excused only for files they hold open (+ sqlite side files); a non-allowed process touching the same file always wins.
- Limits: a writer that exits within milliseconds can't be named (the change is still reported); an edit by the platform's own process itself is not attributable here (Layer 2 record checks/Check C still catch it).
