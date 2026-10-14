# 05 · Self-Tests (our own mini red team, v3)

The test code is written during the event (Claude Code writes and runs them). This file is just the list.

## How
- Each test: **do something bad → check the right alert, event or denial happens.**
- Layer 2 tests (Checks A to C, classifier) run natively as pytest against local processes, no Docker. Vault and Layer 1/3 tests run inside the compose stack (`docker compose exec log-server ...`). Mark container tests `@pytest.mark.docker` and T0 `@pytest.mark.slow`.
- Run each test after its step is merged, and **all tests before every round.**
- Layers can be switched off in `config/layers.yaml`; each layer test also checks that switching it off stops it firing.
- If a test fails, it's a bug in our defence, not in the test.

## Always run first: clean run
| ID | Test | Expected |
|---|---|---|
| T0 | Bank in **fast mode** (`--fast`) for 10,000 transactions, normal team use of `coc-*` commands, no tampering | **Zero alerts, zero layer events.** Any alert is a false alarm and is fixed first. Never run in 1/sec mode (~2.8 hours). |

## Layer 2 · Check A: sealed chain (Step 2)
| ID | Simulate | Expected |
|---|---|---|
| T1a | Encode the same entry twice via `shared/` | Same bytes, same hash |
| T1b | Change one character of a stored entry in the witness DB | Self-check flags it within 5 s, exactly one alert (A7) |
| T1c | Delete a middle entry from the witness DB | Sequence gap from the self-check within 5 s |
| T1d | Swap two entries | Chain break + sequence error |
| T1e | Send an entry signed with a different key | Bad signature |
| T1f | Send the same entry twice (replay) | Sequence error |
| T1g | Send one bad entry, then 5 good ones | Exactly one alert; the 5 good entries are accepted (no cascade) |

## Layer 2 · Check B: outside witness (Step 2)
| ID | Simulate | Expected |
|---|---|---|
| T2a | Stop the agent process (A4) | Silence alert within 15 s, Layer 2 event |
| T2b | Pause the log-server network, reconnect, let queued entries retry | Silence while cut; **no** timestamp alert on the retried batch |
| T2c | Send an entry older than the last accepted one | Non-monotonic timestamp alert |
| T2e | Send an unsigned heartbeat, then replay an old signed one (A5) | Neither counts; silence still fires |
| T2f | Don't answer a hash challenge | Missed-challenge alert within 5 s |

## Layer 2 · Check C: truth check (Step 3)
| ID | Simulate | Expected |
|---|---|---|
| T3a | Agent sends a wrong `from_balance_paise` or `to_balance_paise` | Replay mismatch on that account |
| T3b | **Change a balance directly in the bank DB, no log entry** (A6) | State challenge mismatch; Checks A and B stay green |

## Layer 2 · Tamper classifier (Step 4)
| ID | Simulate | Expected `tamper_type` |
|---|---|---|
| T9a | Each tamper from T1b, T1c, T1d, T1e, T1f, T2a, T2c, T3a, T3b | `entry_edited`, `entry_deleted`, `entries_reordered`, `forged`, `entry_replayed`, `agent_silenced`, `backdated`, `balance_misreported`, `db_edited_without_log` respectively |
| T9b | Edit `amount_paise` of a stored entry (after Step 7) | `entry_edited`, detail names `amount_paise` and old -> new value |
| T9c | T0 clean run | No alerts, so no `tamper_type` at all |

## Layer 2 · Vault + evidence (Step 7)
| ID | Simulate | Expected |
|---|---|---|
| T4a | Use the log-server credential to read, overwrite or delete a vault object | All denied (PutObject only) |
| T4b | Use the vault admin credential to delete a locked object | Denied by compliance-mode object lock |
| T4c | Verify a bundle; then change one byte and verify again | First passes (signature + hash matches witness), second fails |
| T4d | Write a log line | Same line appears under `stream/` in the vault |

## Layer 1 · Tripwire (Steps 8 to 9)
| ID | Simulate | Expected |
|---|---|---|
| T5a | Run each wrapper (`nano`, `vim`, `rm`, `mv`, `cp`, `sed`, `truncate`, `shred`, `cat` on a log, `cd` into the log dir) | Event fired, real log untouched. Block mode: command refused. Deception mode: command "succeeds" on a decoy (A1) |


| T5b | Full path (`/usr/bin/vim.tiny`) or `python` writing a protected file/the bank DB | Backstop alert `backstop:write`, attributed (user, login uid, program); verified in the log-server container |
| T5c | Temp file + rename over the log | Wrapper (`cp`) and backstop both report it |
| T5g | Admin `vim --<profile-id>` and the bank's own writes | No backstop alert (encrypted authorization marker; allowed writer) |
| T5d | Guarded command with a wrong profile-id, then the right one (`vim --<profile-id> app.log`) | Wrong: trips like an intruder. Right: real command runs, logged as `authorized:<cmd>` with the profile, no alert; the profile-id is never stored or sent |
| T5e | Change the guarded command list in `config/layers.yaml`, re-run `install.sh` | Wrappers match the config; ordinary commands outside protected paths run normally, no event |
| T5f | Deception: edit a log with `vim` and save | Real log unchanged; second event carries the attempted diff (old -> new) |

## Layer 1 backstop feeding Layer 2 (Step 9)
| ID | Simulate | Expected |
|---|---|---|
| T6a | Direct edit of a log record (A2) | Flagged immediately from auditd, not at the next heartbeat; bundle has before, after, diff, who |
| T6b | Trigger repeated Layer 2 failures | Escalates to Layer 3 per config |

## Layer 3 · Quarantine (Step 10)
| ID | Simulate | Expected |
|---|---|---|
| T7a | Cut the network between log server and witness for 45 s | Server runs capture → seal → site down → lock out (root included) → QUARANTINED, in that order, no reboot; witness shows quarantined, unverified = unknown |
| T7b | Restore the network | Server reports and stays locked; witness shows the records sealed during the cut; they are shipped and verified |
| T7c | One share, a wrong share, then two right shares | One: nothing. Wrong: approvals reset, alert. Two right: witness-signed unlock carrying the rebuilt secret; server checks its hash, unlocks |
| T7d | Unlock with a bad witness signature or another quarantine id; forged quarantine report | Refused, stays locked; forged report = `forged` alert |
| T7e | A reboot-style command in `layer3` config | Refused at load |
| T7f | Real lockout as root (`docker build -t coc-l3-test -f docker/l3-test/Dockerfile . && docker run --rm --cap-add LINUX_IMMUTABLE --mount type=volume,dst=/var/lib/coc coc-l3-test`) | Root/admin/attacker locked + expired, SSH key logins refused, every terminal session gone, agent and sshd alive; evidence folder append-only (`chattr +a`, needs `CAP_LINUX_IMMUTABLE` + a volume); unlock restores logins. **Result: 18/18 pass** |

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
