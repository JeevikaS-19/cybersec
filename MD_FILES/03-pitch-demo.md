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
**Demo (4 min)**
1. All green. Quick Layer 2 recap: edit an entry → `entry_edited`.
2. **Layer 1:** `nano app.log` → tripwire, command blocked.
3. Bypass with `/usr/bin/nano`, edit a record → **auditd backstop feeds Layer 2**: auditor view shows before / after / diff / **who**.
4. Try to delete that evidence from the vault → **denied** by object lock, even with the vault admin credential.
5. DB edit (A6) → Check C, `db_edited_without_log`.

**Fallback (if auditd failed in Phase 0):** step 3 uses the inotify fallback; say so. Decide by 6:30, rehearse it, never improvise live.

---

## Final · Day 2, 10:00 AM · Product
**Slides (7 min) + demo (4 min)**
1. Hook  2. Problem  3. Detect / Respond / Prove  4. **Live demo**  5. Innovation  6. Scalability  7. Product ready  8. Honest limits + roadmap  9. Who it's for

**Live demo (follows `docs/demo_script.md`)**
1. Normal operation: logs streaming, heartbeats green.
2. **Layer 2:** edit an entry and edit a DB balance → each alert names the tamper type.
3. Stolen admin creds, `nano app.log` → **Layer 1 trips**; `/usr/bin/nano` edit → auditd + Layer 2, before / after / diff / who.
4. Delete the evidence in the vault → denied by object lock.
5. Attacker locks the admin out → **Layer 3 fires**, system FROZEN, attacker's session killed too.
6. Two key holders enter shares in the dashboard → unlocks; every step is in the evidence trail.
7. Show the witness has no SSH (port 22 closed).

### Innovation talking points
- **Truth check (Check C):** catches a direct DB edit with no log entry, which a hash chain alone never sees.
- **Tripwire on habits:** the team never types `nano` on this box; an intruder always does.
- **Break glass with 2-of-3 keys:** the attacker's lockout move freezes them out too; no single person (not even the admin) can unlock.
- **Evidence that outlives the attacker:** write-once vault + witness-held hashes.

### Scalability talking points
- **One agent image, any platform:** a sidecar container; a platform plugs in by mapping its log fields.
- **Witness scales out:** each platform's chain is independent.
- **Vault is standard S3 with object lock:** swap MinIO for any S3-compatible store with compliance mode.
- **Each layer is a config switch:** start with detection only, turn on response layers as trust grows.

### Product-ready talking points
- **One command up:** `docker compose up`.
- **Two users, two jobs:** SOC sees the live timeline and can hit panic; auditor verifies bundles and holds an unlock share.
- **Roles:** no one, not even admins, can edit or delete entries or vault evidence. Every action is itself logged.
- **Compliance fit:** CERT-In 2022 directions (log retention), RBI cybersecurity framework, PCI DSS Requirement 10 (audit logs), SEC 17a-4-style write-once storage.

### Honest limits (say them, judges respect it)
- **Wrappers are bypassable** (full path, another shell). That's why they're detection only; auditd is the enforcement.
- **Docker shares the WSL2 kernel:** Phase 0 results decide which features ran natively and which used fallbacks. Say which.
- **An attacker with root can try to kill the break-glass controller first.** The witness sees missed heartbeats, and the vault already holds everything streamed up to that point.
- **Network cut before a bundle is pushed:** the witness sees the silence, but that bundle is lost. Local encrypted buffer is on the roadmap.
- **An attacker who steals the agent's key can keep signing heartbeats.** Check C and Layer 1/2 events still catch their actions.
- **Unlock shares pass through the witness** to reconstruct the secret. In production, use a threshold scheme where no single party sees the whole secret.
- **Genesis must happen on a clean system.** Future: hardware attestation (TPM).

---

## Judge questions to rehearse
| Question | Answer |
|---|---|
| Can't the attacker just use `/usr/bin/nano`? | Yes, and auditd catches it by exec rule and directory watch. Wrappers are the tripwire, auditd is the lock. |
| Isn't locking everyone out a denial of service? | It's an emergency brake for one trigger: the admin being locked out. Two of three key holders restore service in minutes, and the evidence is safe. |
| Why not just reboot? | A reboot wipes live evidence (processes, connections) and unloads auditd rules. We capture first, then freeze. |
| What if the attacker kills auditd or the agent? | Stopping auditd is itself an audit event, and the witness sees missed heartbeats within 15 s. |
| What if root changes data without writing a log? | Check C: the state challenge compares the bank's real balance with our replay. |
| What if the witness is hacked? | The vault still holds every log line and bundle under object lock; bundle hashes and the vault disagree with any rewrite. |
| Why not just use blockchain? | Object-locked storage plus a signed hash chain gives the same tamper-evidence, faster and cheaper. |
| How does this scale? | Scalability slide. |

## Demo rules
- Same attack order every rehearsal.
- One person drives, one person talks, one person runs attacks.
- Backup screen recording ready for every round.
- Laptop plugged in, Docker Desktop already running with images built, notifications off.
