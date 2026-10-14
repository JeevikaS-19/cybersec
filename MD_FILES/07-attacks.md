# 07 · Attack List (v3, for the 3rd member)

Standalone scripts in `attacks/`, one file per attack (`a1_nano.py`, `a2_fullpath_edit.py`, ...). Each prints what it did and what it expects, so it doubles as the demo script. Most run from the `attacker` container: log in to `log-server` with the stolen demo admin credentials, then act. Base-check attacks (A4, A5, A6) can also run directly inside `log-server`.

| # | Attack | How | Expected | Caught by | Self-test |
|---|---|---|---|---|---|
| A1 | Edit a log with a familiar command | `nano app.log` (also `vim`, `rm`, `sed`, `cat` on a log path) | Command blocked, Layer 1 event, bundle in auditor view | Layer 1 | T5a |
| A2 | Bypass the wrapper | `/usr/bin/nano app.log` or `\nano`, edit a record | auditd execve + dir watch → Layer 2 bundle with before / after / diff / who | Layer 1 backstop, Layer 2 | T5b, T6a |
| A3 | Editor-style save | write a temp file in the log dir, then `mv` it over the log | Directory `-p wa` watch catches the rename | Layer 1 backstop | T5c |
| A4 | Kill the agent | stop the agent process in `log-server` | Silence alert within 15 s, Layer 2 event | Check B | T2a |
| A5 | Fake liveness | after A4, send unsigned or replayed heartbeats | Not counted; silence still fires | Check B | T2e |
| A6 | Edit DB balance directly, no log entry | change a balance in `victim/` SQLite | State challenge mismatch; Checks A and B stay green | Check C | T3b |
| A7 | Edit the witness's stored entry | change one field in the witness DB | Self-check flags it within 5 s | Check A | T1b |
| A8 | Delete the evidence | use log-server creds, then the vault admin creds, to delete a bundle | Denied: PutObject-only policy, then compliance-mode object lock | Vault | T4a, T4b |
| A9 | Lock the admin out | edit `/etc/sudoers` / `/etc/shadow`, or lock the admin account | Layer 3 fires, capture → push → isolate → freeze → lock out → FROZEN; attacker's session killed | Layer 3 | T7a |
| A10 | Unlock with one share | submit a single share on the unlock panel | Refused; two shares unlock | Layer 3 | T7b |
| A11 | SSH to the witness | `ssh witness` / port scan from `attacker` | Port 22 closed, only API port open | Witness hardening | T8a |
| A12 | Kill the break-glass controller first | stop it before triggering A9 | Witness sees missed heartbeats; vault already holds everything streamed. Stated limit | Check B | T2a |
| A13 | Cut the network before a bundle is pushed | drop log-server's network, then tamper | Silence on the witness. Bundle loss is an open TODO (local buffer). Stated limit | Check B | — |

## Build order for the 3rd member
1. A1, A4, A6, A7: needed for Round 1.
2. A2, A3, A8: needed for Round 2 (after auditd + Layer 2 + vault).
3. A9, A10, A11: needed for the Final.
4. A5, A12, A13: nice to have; A12 and A13 mainly support the honest-limits slide.

## Demo order
Final: `03-pitch-demo.md` (A1 → A2 → A8 → A9 → A10 → A11, with A6 as the "only we catch this" moment). Keep a recording of a clean run of the exact sequence as backup.
