# 05 · Self-Tests (our own mini red team)

The red team's real attacks come later. Until then, we break our own system to prove the defence works.

The test code is written during the event (Claude Code writes and runs them). This file is just the list.

## How
- Each test: **do something bad → check the right alert fires.**
- Simplest way to tamper: open the SQLite file and change it directly, or stop a process.
- Run each test after its step is merged, and **all tests before every round.**
- If a test fails, it's a bug in our defence, not in the test.

## Always run first: clean run
| ID | Test | Expected |
|---|---|---|
| T0 | Run the bank in **fast mode** (`06-api-contract.md` / Step 2 of `02-flow.md`) for 10,000 transactions with **no** tampering | **Zero alerts.** Any alert here is a false alarm and must be fixed first. Fast mode finishes in a couple of minutes; never run T0 in normal (1/sec) mode or it takes ~2.8 hours. |

## Layer 1: Sealed chain (after Steps 1 to 4)
| ID | Simulate | Expected alert |
|---|---|---|
| T1a | Encode the same entry twice (via `shared/`) | Same bytes, same hash |
| T1b | Change one character in a stored entry in the witness DB | Periodic self-check flags that entry within 5 s (Layer 1 red), exactly one alert, no new entry needed |
| T1c | Delete an entry from the middle of the witness DB | Sequence gap from the self-check within 5 s |
| T1d | Swap two entries | Chain break + sequence error |
| T1e | Send an entry signed with a different key | Bad signature |
| T1f | Send the same entry twice (replay) | Sequence error |
| T1g | Send one bad entry, then 5 good ones | Exactly one alert; the 5 good entries are accepted (no cascade) |

## Layer 2: Outside witness (after Step 4)
| ID | Simulate | Expected alert |
|---|---|---|
| T2a | Stop the agent process | Silence alert within 15 s |
| T2e | Send an unsigned heartbeat, then replay an old signed one | Neither resets the silence timer; silence alert still fires |
| T2b | Disconnect Laptop A from the hotspot, then reconnect and let the queued entries retry | Silence alert while disconnected; **no** backdating/timestamp alert on the retried batch once reconnected (see Step 4's monotonic check) |
| T2c | Insert an entry with an old timestamp between two recent ones | Non-monotonic timestamp alert |
| T2d | Delete the last 5 entries from the agent's local SQLite on Laptop A, then run `attacks/compare_local.py` | `POST /verify/compare` reports those 5 seqs as `missing_locally` |

## Layer 3: Truth check (after Steps 5 to 9)
| ID | Simulate | Expected alert |
|---|---|---|
| T3a | Agent sends a wrong `from_balance_paise` or `to_balance_paise` | Replay mismatch (Check 1) on the specific account that's wrong |
| T3b | **Change a balance directly in the DB, no log entry** | State challenge mismatch (Check 2), while Layers 1 and 2 stay green |
| T3c | Agent sends a fake, correctly signed transfer | No feed confirmation (Check 3) |
| T3d | Change `to_account` but keep the amount | Feed account mismatch (Check 3) |
| T3e | Feed confirms a transfer the agent never logged | Missing entry (Check 3) |
| T3f | Feed confirmation arrives 10 seconds late | **No alert** (inside the 30 second window) |
| T3g | Add money to one account, no matching debit | Conservation alert (Check 4) |

## After the build (Steps 10 to 13)
| ID | Simulate | Expected alert |
|---|---|---|
| T4a | Use an old, deleted key to sign a past entry | Bad signature / key not valid for that range |
| T4b | Change a stored entry on the witness itself, with the self-check disabled (compromised witness) | Agent's receipts and Laptop C's anchor file disagree with the witness |
| T4c | Agent doesn't answer a random challenge | Missed challenge alert |

## Handover to the red team
Full attack list, scripts and build order: `07-attacks.md`. It already maps each attack to the matching test below, so when the 3rd member's scripts are ready, just run them against these tests:

| Red team attack | Our test |
|---|---|
| A1 edit entry | T1b |
| A2 delete middle | T1c |
| A3 truncate tail | T2d |
| A4 kill agent | T2a |
| A5 backdate | T2c |
| A7 rewrite local chain | T2d |
| A9 stolen key | T4a |
| A10 witness rewrite | T4b |
| A12 DB edit | T3b |
| A13 fake transfer | T3c |
| A14 redirect | T3d |

If a red team attack gets through but our matching test passed, our test was too easy. Fix the test and the defence.

## Before each round
- [ ] T0 clean run (fast mode): zero alerts
- [ ] All tests for steps built so far: pass
- [ ] Demo attacks run in demo order: pass