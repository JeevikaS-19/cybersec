# 03 · Pitch and Demo (v3)

Focus: **innovation, scalability, product ready, amazing pitch.**

**One line:** *Logs that prove they weren't changed, catch the intruder in the act, and lock the door behind them.*

**Story in three layers:** **Layer 2** detects tampering and names what kind (heartbeat + checksums, Checks A to C) → **Layer 1** catches the intruder in the act (tripwire) → **Layer 3** is the last resort (break glass). Every incident becomes a signed bundle in a vault no one can delete from.

---

## Round 1 · 3:00 to 4:00 PM · Idea + skeleton
**Slides (5 min)**
1. **Hook:** A bank insider with admin access edits a balance at 2 a.m. and covers it up. Logs are the only evidence, and the attacker controls them.
2. **Problem:** logs sit on the same machine as the attacker. Admin access = edit access, and most tools only notice afterwards, if at all.
3. **Layer 2, built today:** heartbeat + checksums. Check A (was anything changed?), Check B (is the agent alive and honest?), Check C (does the log match the bank's real state?). Every alert says *what kind* of tampering: edited, deleted, reordered, backdated, forged, silenced.
4. **Coming next:** Layer 1 tripwire (intruder habits give them away), Layer 3 break glass (freeze everything if the admin is locked out).
5. **Prove:** every incident becomes a signed bundle in a write-once vault; its hash goes to the witness.
6. **Skeleton demo** (below).
7. **Plan to Round 2 and Final.**

**Live demo (2 min)**
- Fake bank, agent and witness already running locally; the terminal watcher shows Checks A to C green.
- Edit a stored entry (A7) → Check A red within 5 s, alert says **`entry_edited`**.
- Delete an entry → **`entry_deleted`**. Kill the agent (A4) → **`agent_silenced`**.
- Edit a balance directly in the bank DB (A6) → **Check C red** while A and B stay green, **`db_edited_without_log`**. "Every other log system just missed this."
- If anything breaks: play the backup recording and walk through the story.

---

## Round 2 · 7:30 to 8:30 PM · It works
Run `python demo/demo.py`; the auditor view opens at http://127.0.0.1:8000/. The bank's own side never shows an alert; only the witness does.

**Demo (about 5 min), menu keys in brackets**
1. **Normal:** all three cards green, heartbeat monitor ticking, up spikes labelled `#N` (the witness asking for a record), green down spikes (it matched). "Every record is sealed and checked from outside the machine."
2. **Layer 1 [2] then [1]:** the admin edits with `vim --<profile-id>` → allowed row. The intruder types plain `vim` → red row, rule broken, and the change they *tried* to make. "They think it worked. The real log never changed."
3. **Layer 2 [3]:** the attacker edits a transaction row straight in the database → within ~15 s **Record #N**: expected vs found, the changed amount in red, hashes underneath.
4. **Check C [4]:** a balance changed with no transaction → `db_edited_without_log`.
5. **Layer 3 [5]:** cut the network → monitor goes flat → after 45 s "Banking server has quarantined itself. All users logged out." **[6]** plug it back → the server reports the records it sealed during the cut and stays locked → press Approve twice → Connected.

**If something fails:** reset with **[r]** and continue from the next step; backup recording for Layer 3 (it takes ~60 s).

---

## Final · Day 2, 10:00 AM · Product
**Slides (7 min) + demo (5 min)**
1. Hook  2. Problem  3. Three layers  4. **Live demo**  5. Innovation  6. Scalability  7. Product ready  8. Honest limits + roadmap  9. Who it's for

**Live demo (Docker: three real servers).** Before: `python docker/ctl.py reset`, open http://127.0.0.1:8000/, have `python docker/ctl.py shares` output for two "key holders". Backup: the page's **Preview** switch (Normal / Layer 1 / Layer 2 / Layer 3) works with no server at all.
1. **Normal:** all green; heartbeat monitor asks for `#N` records and they match. "The witness is a separate server with no SSH; the bank never shows an alert."
2. **Layer 1:** `ctl.py admin` (allowed, logged) then `ctl.py intruder`: stolen password over SSH, `vim` + `rm` on the log → red rows with user + source IP, rule broken, the edit they *tried*; real log untouched.
3. **Layer 1 backstop:** the attacker uses `/usr/bin/vim.tiny` by full path → `backstop:write`, attributed. "Wrappers are the tripwire; the backstop is the lock."
4. **Layer 2:** `ctl.py tamper-record` → **Record #N** expected vs found in red within ~15 s; `ctl.py tamper-balance` → Check C.
5. **Layer 3:** `ctl.py cut` → heartbeat flat → 45 s → "Banking server has quarantined itself": everyone incl. root logged out and locked, SSH keys refused, bank paused, evidence append-only. `ctl.py restore` → server reports the records it sealed during the cut, stays locked → two holders paste shares → unlocked.

### Innovation talking points
- **Record checks from outside:** the witness asks for record `#42` and compares the bank's row *now* with the sealed copy, field by field: edits made straight in the database are caught, not just log edits.
- **Truth check (Check C):** a balance changed with no transaction is caught even when every record looks fine.
- **Deception tripwire:** the team uses `<cmd> --<profile-id>`; an intruder's habitual `vim` edits a decoy, and we capture what they tried to change.
- **Quarantine on network cut:** cutting the network to work unseen is itself the trigger; the server locks everyone out (root too) and keeps sealing records offline.
- **Shamir 2-of-3 unlock:** even a hacked witness can't unlock; the server checks the rebuilt secret against a hash it got at setup.

### Scalability talking points
- **Latches onto any platform by config:** `config/platform.yaml` maps tables, columns and units (SQLite or PostgreSQL; tested on a PostgreSQL bank shaped like the team's app with concurrent, out-of-order commits).
- **Witness scales out:** each platform registers its own key and chain.
- **Each layer is a config switch** (`config/layers.yaml`): start with detection, turn on response layers as trust grows.

### Product-ready talking points
- **One command up:** `python docker/ctl.py up`; production install: `deploy/install-log-server.sh` + systemd services; builds work offline.
- **Nothing hardcoded:** commands, paths, timings, thresholds, lockout commands, key holders: all config.
- **Tested:** 56 automated tests, 10,000-transaction clean run with zero false alarms, real lockout proven as root in a container (18/18).
- **Compliance fit:** CERT-In 2022 directions (log retention), RBI cybersecurity framework, PCI DSS Requirement 10 (audit logs).

### Honest limits (say them, judges respect it)
- **Wrappers are bypassable** (full path, another tool). That's why there's a backstop. auditd is host-only, so inside containers the backstop uses inotify + /proc; a writer that exits within milliseconds is caught but can't always be named.
- **Root can try to kill the agent first.** The witness flags silence within 15 s and treats 45 s as quarantine; everything sealed before that is already outside.
- **An attacker who steals the agent's key can keep sending heartbeats.** Record checks and Check C still catch changes to the bank's data.
- **Unlock shares pass through the witness** to rebuild the secret; re-issue shares after every unlock.
- **Genesis must happen on a clean system**, and Check C learns each starting balance once. Future: hardware attestation (TPM).
- **Whoever controls the hypervisor/console can always get in.**

---

## Judge questions to rehearse
| Question | Answer |
|---|---|
| Can't the attacker just use `/usr/bin/nano`? | Yes, and the backstop catches the write and names who did it. Wrappers are the tripwire, the backstop is the lock. |
| Isn't locking everyone out a denial of service? | It fires on one signal: the server losing its witness. Two of three key holders restore it in minutes, and nothing is lost: records keep being sealed offline. |
| Why not just reboot? | A reboot wipes live evidence (processes, connections). We capture first, then lock. |
| What if the attacker kills the agent? | The witness sees missed heartbeats within 15 s; everything already sealed is outside the server. |
| What if root changes data without writing a log? | Record checks compare the row now with the sealed copy; Check C compares real balances with our replay. |
| What if the witness is hacked? | It holds public keys only, so it can't forge records; it can't unlock without two Shamir shares. |
| Why not blockchain? | A signed hash chain checked by an outside witness gives the same tamper-evidence, faster and cheaper. |
| How does it attach to our bank? | One config file maps your tables; your code doesn't change. |

## Demo rules
- Same attack order every rehearsal.
- One person drives, one person talks, one person runs attacks.
- Backup screen recording ready for every round.
- Laptop plugged in, Docker Desktop already running with images built, notifications off.
