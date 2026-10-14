# 01 · Working Rules

Copy this into `AGENTS.md` (Antigravity) and `CLAUDE.md` (Claude Code).

## Who does what
| Who | Role |
|---|---|
| **Antigravity (Gemini)** | Builder. Writes code one small step at a time. Wherever `LAYERS_PLAN.md` says "Claude Code" should build, read it as the builder. |
| **Claude Code** | Reviewer and tester. Checks the code, writes and runs tests, reports. |
| **Human (Jeev / Jaganath / 3rd member)** | Decides. Approves every step, commits, understands the code. |

## The loop (every single step)
1. **Human** picks the next step from `02-flow.md`.
2. **Antigravity** replies with a plan in max 5 lines: files it will touch, what it will add. **No code yet.**
3. **Human** says OK, or changes the plan.
4. **Antigravity** writes the code for that step only.
5. **Antigravity** explains in plain words (max 5 lines) what the code does.
6. **Claude Code** reviews the diff against `02-flow.md` / `06-api-contract.md` / `LAYERS_PLAN.md` and runs the matching tests from `05-self-tests.md`.
7. **Claude Code** reports: PASS / FAIL, bugs found, max 5 lines.
8. If FAIL: back to Antigravity with the exact error. If PASS: human commits and merges.
9. Human can explain the step out loud before moving on. If not, ask Antigravity to explain, don't move on.

## Naming (use exactly)
- **Layer 2** heartbeat + checksum (built first): contains **Check A** sealed chain, **Check B** outside witness, **Check C** truth check, and the tamper classifier (`tamper_type` on every alert).
- **Layer 1** command tripwire (built second). **Layer 3** break glass (built last).
- Use these names exactly in code, UI and slides. Checks A to C are parts of Layer 2, never separate layers.

## Rules for Antigravity (builder)
- Ask before acting. Never start the next step on your own.
- One step = one small change. If a step looks bigger than ~100 lines, split it and say so.
- Only touch the folders for the current step (owners in `02-flow.md`).
- Follow the entry format, routes and signed-field lists in `06-api-contract.md` exactly. Never change field or route names without asking.
- Amounts are **integer paise**, two fields: `from_balance_paise`, `to_balance_paise`. Never floats.
- No balance or reconciliation logic in `agent/`. It lives in `witness/`.
- Canonical encoding, hashing and signing live in `shared/` only, imported everywhere else.
- New layer code goes in new modules under `layers/`. Changing a base module (`shared/`, `agent/`, `witness/`) for a layer: add the smallest hook and say what you changed.
- Every check and layer can be switched on and off in `config/layers.yaml`.
- Layer 3 order is fixed: capture → push → isolate → freeze → lock out → report. **Never reboot.**
- Secrets: private keys, Shamir shares, the revert key and vault credentials are never printed, logged or committed. Store only hashes of the revert key and break-glass secret.
- No new libraries without asking. Allowed: FastAPI, uvicorn, requests, cryptography, sqlite3, streamlit, pycryptodome (Shamir only), minio (Python client), pyyaml, pytest, ruff (dev-only). System tools in containers: auditd, iptables, chattr, inotify-tools.
- No cloud services. Everything runs in Docker on one laptop.
- If unsure, ask one question. Don't guess.

## Rules for Claude Code (reviewer)
- Review, don't rewrite. Point to the line and say what's wrong.
- Fixes: suggest them, only apply if the human says so.
- Always check, every review:
  - matches the step in `02-flow.md`, the routes and signed fields in `06-api-contract.md`
  - no floats in amounts; two balance fields
  - crypto and secrets: keys, shares, revert key never printed, sent or stored in plain form
  - witness never trusts the agent's balances or challenge replies on their own
  - canonical encoding imported from `shared/`, not reimplemented
  - Layer 3 step order, no reboot path
  - vault: log-server credential is PutObject only
  - nothing breaks the clean-run test (T0)
- Run the tests for the step, plus T0 before any merge to `main`.

## Team rules
- One repo. Folders and owners: see `02-flow.md` (Folders and owners).
- `shared/` is written once in Step 2a and only changed by Jeev after that, with a heads-up in chat.
- Two AI agents never edit the same folder at the same time.
- `main` must always `docker compose up` and demo. Work on a branch per step.
- Time-box: if a step is stuck for 45 minutes, use its fallback and move on.
- Freeze 1 hour before each round. No new features, only fixes and rehearsal.
- Wording: tampering is "detected" and "provable", never "impossible". Layers 1 and 3 block or freeze actions; say that, but never claim the system can't be beaten.
