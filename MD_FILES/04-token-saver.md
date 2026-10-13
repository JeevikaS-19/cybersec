# 04 · Token Saver

Copy into `AGENTS.md` and `CLAUDE.md` under the rules.

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