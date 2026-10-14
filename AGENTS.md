# Chain of Custody: Agent Rules (Antigravity)

> Copied from `MD_FILES/01-rules.md` and `MD_FILES/04-token-saver.md`. If they change, re-copy. Design: `MD_FILES/LAYERS_PLAN.md`. Steps and owners: `MD_FILES/02-flow.md`. Routes and fields: `MD_FILES/06-api-contract.md` (tiebreaker).


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

---

## Rules for the AI
- **Read only what the step needs.** Read the current step in `02-flow.md`, the routes it uses in `06-api-contract.md`, the matching section of `LAYERS_PLAN.md`, and the files in that step's folder. Don't scan the whole repo.
- **Don't re-read files** you already read this session unless they changed.
- **Edit, don't rewrite.** Change only the lines that need changing. Never reprint a whole file.
- **Short replies.** Plan: max 5 lines. Explanation: max 5 lines. Review: max 5 lines. No intros, no recaps.
- **No extras.** No READMEs, comments on every line, docstrings, type stubs, example files or "nice to have" features unless asked.
- **No new libraries.** Use the allowed list in `01-rules.md`.
- **Run only the tests for this step**, plus T0 (fast mode) before merging. Don't rebuild Docker images unless a Dockerfile changed.
- **Show only the error line** from failing output, not the full log.
- **Ask one question instead of guessing.** A wrong guess costs more tokens to undo.
- **Stop when the step is done.** Don't start the next one.

## Rules for us (the humans)
- **One step per prompt.** "Do Step 5 from 02-flow.md" beats "build the witness".
- **Point to sections**, don't paste the spec again.
- **Paste the exact error**, not "it doesn't work".
- **New session per step.** Clear or start fresh after each step is merged so old context doesn't pile up. In Claude Code, use `/clear` between steps and `/compact` if a session gets long.
- **Antigravity builds, Claude Code reviews.** Don't ask both to write the same thing.
- **Stagger accounts.** Limits reset roughly every 5 hours. Don't burn both Claude Code accounts at once. Note when each one hit its limit.
- **Save heavy reviews** for crypto, evidence bundles, Layer 3 and reconciliation code. UI code only gets reviewed if it's broken.

## Good vs bad prompts
| Bad | Good |
|---|---|
| "Build the agent" | "Do Step 2b from 02-flow.md. Plan first." |
| "Fix it" | "Step 2c test fails: `seq mismatch at 12`. Find the cause." |
| "Review everything" | "Review the diff for Step 4 against 02-flow.md and 06-api-contract.md. Run tests T9a to T9c." |
| "Explain the code" | "Explain the prev_hash check in 3 lines." |