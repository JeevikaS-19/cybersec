# 01 · Working Rules

Copy this into `AGENTS.md` (Antigravity) and `CLAUDE.md` (Claude Code).

## Who does what
| Who | Role |
|---|---|
| **Antigravity (Gemini)** | Builder. Writes code one small step at a time. |
| **Claude Code** | Reviewer and tester. Checks the code, runs tests, reports. |
| **Human (Jeev / Jaganath)** | Decides. Approves every step, commits, understands the code. |

## The loop (every single step)
1. **Human** picks the next step from `02-flow.md`.
2. **Antigravity** replies with a plan in max 5 lines: files it will touch, what it will add. **No code yet.**
3. **Human** says OK, or changes the plan.
4. **Antigravity** writes the code for that step only.
5. **Antigravity** explains in plain words (max 5 lines) what the code does.
6. **Claude Code** reviews the diff against `02-flow.md` / `06-api-contract.md` and runs the matching tests from `05-self-tests.md`.
7. **Claude Code** reports: PASS / FAIL, bugs found, max 5 lines.
8. If FAIL: back to Antigravity with the exact error. If PASS: human commits and merges.
9. Human can explain the step out loud before moving on. If not, ask Antigravity to explain, don't move on.

## Rules for Antigravity (builder)
- Ask before acting. Never start the next step on your own.
- One step = one small change. If a step looks bigger than ~100 lines, split it and say so.
- Only touch the folder for the current step.
- Follow the entry format and routes in `02-flow.md` / `06-api-contract.md` exactly. Never change field or route names without asking.
- Amounts are **integer paise**, two fields: `from_balance_paise`, `to_balance_paise`. Never floats, never a single `running_balance_paise`.
- No balance or reconciliation logic in `agent/`. It lives in `witness/`.
- Canonical-encoding and hashing code lives in `shared/` only, imported by `agent/` and `witness/` — never copy-pasted into either.
- No new libraries without asking. Allowed: FastAPI, uvicorn, requests, cryptography, sqlite3, streamlit, pytest, ruff (dev-only, not shipped in the running app).
- No internet services. Everything runs on the 3 laptops over the hotspot.
- If unsure, ask one question. Don't guess.

## Rules for Claude Code (reviewer)
- Review, don't rewrite. Point to the line and say what's wrong.
- Fixes: suggest them, only apply if the human says so.
- Always check, every review:
  - matches the format and step in `02-flow.md`, and the routes in `06-api-contract.md`
  - no floats in amounts; two balance fields, not one
  - crypto: keys never printed or sent, private keys never leave their own laptop
  - witness never trusts the agent's balance or state-challenge reply as truth on its own
  - canonical encoding is imported from `shared/`, not reimplemented
  - nothing breaks the clean-run test (fast mode, see `05-self-tests.md` T0)
- Run the tests for the step, plus the clean-run test before any merge to `main`.

## Team rules
- One repo. Folders: `shared/`, `victim/`, `agent/`, `witness/`, `feed/`, `dashboard/`, `attacks/`, `tests/`.
- Folder owners: Jeev = `shared/`, `agent/`, `witness/` · Jaganath = `victim/`, `dashboard/` · 3rd member = `feed/`, `attacks/`.
- `shared/` is written once in Step 1 and only changed by Jeev after that, with a heads-up in chat (both `agent/` and `witness/` depend on it).
- Two AI agents never edit the same folder at the same time.
- `main` must always run and demo. Work on a branch per step.
- Time-box: if a step is stuck for 45 minutes, use the fallback in `02-flow.md` and move on.
- Freeze 1 hour before each round. No new features, only fixes and rehearsal.