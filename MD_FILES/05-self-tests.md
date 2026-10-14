# 05 · Self-Tests (our own mini red team, v3)

The test code is written during the event (Claude Code writes and runs them). This file is just the list.

## How
- Each test: **do something bad → check the right alert, event or denial happens.**
- Base-check tests run as pytest against the services; layer tests run inside the compose stack (`docker compose exec log-server ...`). Mark container tests `@pytest.mark.docker` and T0 `@pytest.mark.slow`.
- Run each test after its step is merged, and **all tests before every round.**
- Layers can be switched off in `config/layers.yaml`; each layer test also checks that switching it off stops it firing.
- If a test fails, it's a bug in our defence, not in the test.

## Always run first: clean run
| ID | Test | Expected |
|---|---|---|
| T0 | Bank in **fast mode** (`--fast`) for 10,000 transactions, normal team use of `coc-*` commands, no tampering | **Zero alerts, zero layer events.** Any alert is a false alarm and is fixed first. Never run in 1/sec mode (~2.8 hours). |

## Check A: sealed chain (Step 3)
| ID | Simulate | Expected |
|---|---|---|
| T1a | Encode the same entry twice via `shared/` | Same bytes, same hash |
| T1b | Change one character of a stored entry in the witness DB | Self-check flags it within 5 s, exactly one alert (A7) |
| T1c | Delete a middle entry from the witness DB | Sequence gap from the self-check within 5 s |
| T1d | Swap two entries | Chain break + sequence error |
| T1e | Send an entry signed with a different key | Bad signature |
| T1f | Send the same entry twice (replay) | Sequence error |
| T1g | Send one bad entry, then 5 good ones | Exactly one alert; the 5 good entries are accepted (no cascade) |

## Check B: outside witness (Step 3)
| ID | Simulate | Expected |
|---|---|---|
| T2a | Stop the agent process (A4) | Silence alert within 15 s, Layer 2 event |
| T2b | Pause the log-server network, reconnect, let queued entries retry | Silence while cut; **no** timestamp alert on the retried batch |
| T2c | Send an entry older than the last accepted one | Non-monotonic timestamp alert |
| T2e | Send an unsigned heartbeat, then replay an old signed one (A5) | Neither counts; silence still fires |
| T2f | Don't answer a hash challenge | Missed-challenge alert within 5 s |

## Check C: truth check (Step 4)
| ID | Simulate | Expected |
|---|---|---|
| T3a | Agent sends a wrong `from_balance_paise` or `to_balance_paise` | Replay mismatch on that account |
| T3b | **Change a balance directly in the bank DB, no log entry** (A6) | State challenge mismatch; Checks A and B stay green |

## Vault + evidence (Step 5)
| ID | Simulate | Expected |
|---|---|---|
| T4a | Use the log-server credential to read, overwrite or delete a vault object | All denied (PutObject only) |
| T4b | Use the vault admin credential to delete a locked object | Denied by compliance-mode object lock |
| T4c | Verify a bundle; then change one byte and verify again | First passes (signature + hash matches witness), second fails |
| T4d | Write a log line | Same line appears under `stream/` in the vault |

## Layer 1: tripwire (Steps 6 to 7)
| ID | Simulate | Expected |
|---|---|---|
| T5a | Run each wrapper (`nano`, `vim`, `rm`, `mv`, `cp`, `sed`, `truncate`, `shred`, `cat` on a log, `cd` into the log dir) | Event fired, bundle pushed, real command **not** run (A1) |
| T5b | Run `/usr/bin/nano` / `\nano` / `python -c` to write a log | auditd (or inotify fallback) catches it (A2) |
| T5c | Temp file + rename over a log | Directory watch catches it (A3) |
| T5d | `coc-unlock` with a wrong key, then the right key | Wrong: refused + logged. Right: originals restored for that session only + logged |
| T5e | `coc-view`, `coc-status`, `coc-verify` | Work, fire no event |

## Layer 2: hooks (Step 8)
| ID | Simulate | Expected |
|---|---|---|
| T6a | Direct edit of a log record (A2) | Flagged immediately from auditd, not at the next heartbeat; bundle has before, after, diff, who |
| T6b | Trigger repeated Layer 2 failures | Escalates to Layer 3 per config |

## Layer 3: break glass (Step 9)
| ID | Simulate | Expected |
|---|---|---|
| T7a | Edit `/etc/sudoers` (A9); also test the panic button | Steps run in order (capture → push → isolate → freeze → lock out → FROZEN), no reboot, attacker session killed |
| T7b | Unlock with 1 share, then with each pair of 2 (A10) | 1 fails; any 2 succeed; unlock reverses 5, 4, 3 and is logged |
| T7c | While FROZEN, try to write a log or reach anything but vault + witness | Denied |
| T7d | Send an unlock command with a bad witness signature or wrong secret | Refused, stays FROZEN |

## Witness hardening
| ID | Simulate | Expected |
|---|---|---|
| T8a | Connect to port 22 on the witness from `attacker` (A11) | Closed; only the API port answers |

## Attack → test map
See the table in `07-attacks.md` (A1 T5a, A2 T5b/T6a, A3 T5c, A4 T2a, A5 T2e, A6 T3b, A7 T1b, A8 T4a/T4b, A9 T7a, A10 T7b, A11 T8a). If an attack gets through but its test passed, the test was too easy. Fix both.

## Before each round
- [ ] T0 clean run (fast mode): zero alerts
- [ ] All tests for steps built so far: pass
- [ ] Demo attacks in demo order: pass
