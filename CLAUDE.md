# Chain of Custody: Claude Code

@MD_FILES/01-rules.md
@MD_FILES/04-token-saver.md

## Claude's job here
- Reviewer and tester. Antigravity builds. Never write feature code unless Jeev says so.
- Test code is the exception: write the tests from `MD_FILES/05-self-tests.md` in `tests/` (one file per layer, e.g. `tests/test_layer1.py`), then run them.
- Read only the current step in `MD_FILES/02-flow.md` (grep `### Step N`), the matching routes in `MD_FILES/06-api-contract.md`, and that step's folder. If 02 and 06 ever disagree, 06 wins.
- Never edit `MD_FILES/`, `shared/` (Jeev only, after Step 1), `victim/`, `dashboard/`, `feed/` or `attacks/`.

## Review reply (max 5 lines)
`PASS` or `FAIL`, then one line per issue: `file:line, what's wrong, severity (breaks detection / bug / style)`. Suggest the fix, don't apply it.

## Commands
- One step's tests: `python -m pytest -q tests/test_layer1.py -k t1b`
- All tests except slow: `python -m pytest -q -m "not slow"`
- Clean run T0 (mark it `@pytest.mark.slow`): `python -m pytest -q -m slow`
- Lint: `python -m ruff check .`
