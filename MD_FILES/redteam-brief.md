# Red Team mode: threat model and rules

You generate adversarial test scenarios against the chain-of-custody witness and
report which are detected. The point is to find gaps before the IBM demo, then
help the team close them. You do not "win" by editing the thing being tested.

## What the attacker is assumed to hold
- Root on ct105 (the bank host): the bank log, the PostgreSQL database, the
  monitor process, and the current shared HMAC secret.
- NOT: the witness host, the monitor's Ed25519 private key history, or any past
  HMAC secret. The witness is a separate machine the bank admin cannot reach into.

This matches the README: root on ct105 can forge new events and lie to the bank
API, so the system is a demonstration against record edits while the bank keeps
running normally, not a guarantee against a fully compromised host. Keep scenarios
inside that honest boundary. Do not claim detection the design does not offer.

## Hard rules
- Never edit `witness/**`, `deploy/ct105/layer1/monitor.py`, `witness/records.js`,
  or any signing/verification code. Those are under test.
- Every scenario is reversible: take a backup, change state, let the witness
  react, then restore in a `trap ... EXIT`. Account balances are never touched.
- Reuse the existing demo patterns: host guard (`COC_SKIP_HOST_CHECK`), IST
  timestamps, pause longer than the poll interval so each case is visible alone.
- Each scenario file states, at the top: target layer, what it changes, and the
  expected witness result (caught / missed / rate-limited).

## Verification paths to exercise
Layer 1 (seal chain, `monitor.py` + auditd tripwire):
- in-place edit, append, truncate, remove of the watched log
- an edit followed by a consistent re-seal attempt before the seal ships
- an edit at a chain boundary

Layer 2 (`rowHash` over the 7 allowed fields + bank reconciliation):
- amount, type, status change on a committed row
- replay / reorder / duplicate a committed id
- a row the bank API reports differently from the witnessed copy
- behavior when the bank check is rate-limited (must read as rate-limit, not tamper)

Layer 3 (heartbeat silence → presumed quarantine, dry-run):
- network cut for N seconds; silence alert at 90 s, presumed quarantine at 45 s
- restore via the signed restore-request path

## Output: the coverage table
After running a batch, produce / update `redteam/coverage.md` with one row per
scenario: id, target layer, what changed, caught?, which check caught it, which
alert fired, time to detect. List misses separately at the bottom with a one-line
hypothesis for why each slipped through. For a miss, switch to a planning view
and explain the gap and the kind of fix; the team writes the fix themselves.
