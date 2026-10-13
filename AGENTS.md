# Chain of Custody: Agent Rules (Antigravity)

> Copied from `MD_FILES/01-rules.md` and `MD_FILES/04-token-saver.md`. If they change, re-copy. Steps: `MD_FILES/02-flow.md`. Routes and fields: `MD_FILES/06-api-contract.md` (tiebreaker).


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

---

## Rules for the AI
- **Read only what the step needs.** Read `02-flow.md` and `06-api-contract.md` for the current step and the files in that step's folder. Don't scan the whole repo.
- **Don't re-read files** you already read this session unless they changed.
- **Edit, don't rewrite.** Change only the lines that need changing. Never reprint a whole file.
- **Short replies.** Plan: max 5 lines. Explanation: max 5 lines. Review: max 5 lines. No intros, no recaps.
- **No extras.** No READMEs, comments on every line, docstrings, type stubs, example files or "nice to have" features unless asked.
- **No new libraries.** Use the allowed list in `01-rules.md` (FastAPI, uvicorn, requests, cryptography, sqlite3, streamlit, pytest, ruff).
- **Run only the tests for this step**, plus the clean-run test (fast mode) before merging.
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
- **Save heavy reviews** for crypto and reconciliation code. UI code only gets reviewed if it's broken.

## Good vs bad prompts
| Bad | Good |
|---|---|
| "Build the agent" | "Do Step 3 from 02-flow.md. Plan first." |
| "Fix it" | "Step 4 test fails: `seq mismatch at 12`. Find the cause." |
| "Review everything" | "Review the diff for Step 5 against 02-flow.md and 06-api-contract.md. Run tests T5a to T5c." |
| "Explain the code" | "Explain the prev_hash check in 3 lines." |
