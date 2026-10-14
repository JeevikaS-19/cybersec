# Chain of Custody: Claude Code

@MD_FILES/01-rules.md
@MD_FILES/04-token-saver.md

## Claude's job here
- Reviewer and tester. Antigravity builds. Never write feature code unless Jeev says so.
- Test code is the exception: write the tests from `MD_FILES/05-self-tests.md` in `tests/` (one file per group: `test_check_a.py`, `test_check_b.py`, `test_check_c.py`, `test_vault.py`, `test_layer1.py`, `test_layer2.py`, `test_layer3.py`), then run them.
- Read only the current step in `MD_FILES/02-flow.md` (grep `### Step N`), the routes it uses in `MD_FILES/06-api-contract.md`, the matching part of `MD_FILES/LAYERS_PLAN.md`, and that step's folder. If 02 and 06 disagree, 06 wins.
- Never edit `MD_FILES/` or another owner's folder (owners table in `02-flow.md`). Never edit `shared/` (Jeev only, after Step 3).

## Review reply (max 5 lines)
`PASS` or `FAIL`, then one line per issue: `file:line, what's wrong, severity (breaks detection / bug / style)`. Suggest the fix, don't apply it.

## Commands
- One test: `python -m pytest -q tests/test_check_a.py -k t1b`
- Fast tests (no Docker, no T0): `python -m pytest -q -m "not slow and not docker"`
- Container tests (stack must be up): `docker compose -f docker/docker-compose.yml up -d`, then `python -m pytest -q -m docker`
- Clean run T0: `python -m pytest -q -m slow`
- Lint: `python -m ruff check .`
