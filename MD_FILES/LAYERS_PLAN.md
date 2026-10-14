# Chain of Custody v3: Three-Layer Defence Plan

Hackurity 2026, PS-6. This is the whole plan (v3 replaces the old v2 build). The detection base (v2's checks, now called **Check A** sealed chain, **Check B** outside witness, **Check C** truth check) is built minimally first, then the three response layers on top. Build order, owners and timeline: `02-flow.md`. Routes: `06-api-contract.md`. Read this whole file before writing any code.

## Ground rules for the builder

Antigravity builds; Claude Code reviews and tests (`01-rules.md`). Where this file says "Claude Code", read it as the builder.


- **Build the base minimally, then don't rebuild it.** The base (Checks A to C: per-entry checksums, balance reconciliation, signing keys, heartbeat + random witness challenges, SOC and auditor views) is `02-flow.md` Steps 2 to 3. Layers reuse it. Keep `docs/integration_map.md` up to date: where heartbeat, checksum verification, signing keys and the dashboard live, and which functions the layers call. Key rotation is slide-only this event.
- **Ask before changing v2 core modules.** New code goes in new modules. If a v2 function needs a hook, add the smallest possible hook and say what you changed.
- **Every layer can be switched on and off in config** so we can demo them one at a time.
- Language: **Python 3.11+**. Tests: **pytest**. Keep code readable over clever.
- After each phase, explain in plain words what was built and why, so the team can present it.

## Environment

Docker Desktop on Windows (WSL2 backend), one `docker compose up` for the whole demo.

| Container | Role | Notes |
|---|---|---|
| `log-server` | The protected machine. Runs the app logs, the agent, and the three layers | Needs extra capabilities (see Phase 0) |
| `witness` | Receives hashes and heartbeats only | **No sshd installed.** Exposes only the heartbeat/challenge API port |
| `vault` | Evidence store | MinIO with object lock enabled |
| `dashboard` | v2 SOC + auditor views, extended | |
| `attacker` | Simulated hacker machine on the same network | Used only for the demo |

### Phase 0: kernel feature spike (do this first, it decides the rest)

Docker containers share the WSL2 Linux kernel, and some features below may not work inside a container. Before building anything, write a small script that checks, inside `log-server`:

1. **auditd**: can it load watch rules and execve rules? (needs `CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`; the audit subsystem is not namespaced, so only one auditd can own it)
2. **fanotify** permission events (needs `CAP_SYS_ADMIN`)
3. **chattr +a / +i** on the log volume (needs `CAP_LINUX_IMMUTABLE`, and the filesystem must support it; overlayfs often does not, so mount the log directory as a volume)
4. **iptables** inside the container (needs `CAP_NET_ADMIN`)

Record results in `docs/phase0_results.md`. For anything that fails, use the fallback listed in the relevant layer and note it as a known limitation for the judges. Do not spend more than a short time fighting a feature; fallbacks are fine for the demo.

## Shared piece: evidence bundles and the vault (build before the layers)

Every layer saves a copy. They all use this one module.

**Vault (MinIO)**
- Bucket created with object locking on, default retention in **compliance mode** (short period such as 1 day for the demo).
- The log server gets credentials with a policy that allows **`PutObject` only**: no read, no delete, no overwrite.
- A separate auditor credential has read-only access.
- Demo moment: show that even the vault admin credential cannot delete a locked object.

**Continuous streaming ("before" copy)**
- Every log entry is pushed to the vault as it is written, so the original version always exists off-box.

**Evidence bundle ("after" copy + attribution)**, built when any layer fires:
- `layer` (1, 2 or 3), `trigger`, timestamp
- who: `auid` (original login user), uid, process, executable, source IP if remote
- snapshot of the affected log file(s) and their hashes
- diff against the last good version in the vault, where relevant
- relevant auditd records
- signed with the v2 signing key, and the bundle hash sent to the witness so the bundle itself is tamper-evident

**Module**: `layers/common/evidence.py` (build, sign, push) and `layers/common/events.py` (one internal event format all layers emit).

**Open decision, do not build yet:** what happens if the attacker cuts the network before a bundle can be pushed. Leave a clear `TODO` stub where a local encrypted buffer would go. The witness already detects the silence through missed heartbeats.

## Layer 1: custom command tripwire

**Idea.** On the log server, common commands are replaced with tripwires. The real team uses a custom command set and never types plain `nano` there. An intruder types familiar commands out of habit and trips the alert. The company can restore original commands only with a revert key.

**Build**
- A wrapper directory placed first in `PATH` (for example `/opt/trip/bin`) with wrappers for: `nano`, `vi`, `vim`, `gedit`, `rm`, `mv`, `cp`, `sed`, `truncate`, `shred`, `cat` on log paths. `cd` is a shell builtin, so handle it with a shell function in the system-wide shell profile.
- Each wrapper: emits a Layer 1 event, triggers an evidence bundle, sends an alert to the witness/dashboard, then blocks the action (does not run the real command).
- The team's custom command set, for example `coc-view`, `coc-status`, `coc-verify`, for legitimate read-only work.
- **Revert key**: `coc-unlock` asks for a key, checks it against a stored hash (never the key itself), and if correct restores the original commands for that session only, and logs that it happened.

**Backstop (important).** Wrappers are easy to bypass (`/usr/bin/nano`, `\nano`, Python, another shell). So also add auditd rules:
- execve rules for the real binaries above, so running them by full path is still caught
- write/attribute watches (`-p wa`) on the log **directory**, not just files, so editors that save via temp file + rename are caught

Present the wrappers as detection, with auditd as the real enforcement.

**Fallback if auditd fails in Phase 0:** inotify watch on the log directory plus process lookup for attribution.

**Module**: `layers/l1_tripwire/`

## Layer 2: heartbeat + checksum hooks (v2 logic, new responses)

**Do not rewrite the heartbeat or checksum.** Only connect them to the new response system.

**Build**
- When v2 detects a checksum mismatch, a failed random challenge, or a missed heartbeat, emit a Layer 2 event.
- On that event: build an evidence bundle with the tampered "after" version, the diff against the vault's "before" copy, and the auditd records showing who changed it and with which program.
- Also feed Layer 1's auditd file-write events into the same check, so a direct edit is flagged immediately instead of waiting for the next heartbeat.
- Severity setting: decide which Layer 2 events escalate to Layer 3 automatically (config value, default: repeated failures or any failure while an admin lockout is in progress).

**Module**: `layers/l2_hooks/`

## Layer 3: break glass

**Idea.** An emergency brake. If the attacker locks the admin or company out, the system freezes and locks **everyone** out, attacker included, until two of three key holders unlock it.

**Triggers**
- Admin lockout signals: changes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`, or admin `authorized_keys`; the admin account being locked or removed from sudo
- Escalation from Layer 2 (per config)
- Manual panic button in the SOC view

**Response, in this exact order** (capture before destroying anything; **do not reboot**, a reboot wipes live evidence and unlocks auditd rules)
1. **Capture**: process list, network connections (`ss -tnp`), logged-in sessions, latest auditd records, hashes of all log files
2. **Push** the final evidence bundle to the vault, hash to the witness
3. **Isolate**: iptables default DROP, allowing only the vault and witness
4. **Freeze**: make the log directory immutable (`chattr +i`, or remount read-only if chattr failed in Phase 0) and stop writers
5. **Lock out**: lock all interactive accounts and kill their sessions
6. Report "FROZEN" to the witness and dashboard

**Unlock: 2-of-3 split key**
- Use Shamir's Secret Sharing (`pycryptodome`, `Crypto.Protocol.SecretSharing.Shamir`). Three shares, any two reconstruct.
- Holders for the demo: **auditor, SOC lead, legal**.
- The log server stores only a hash of the secret.
- Shares are entered through the dashboard/witness, never typed on the frozen log server. The witness sends a signed unlock request; the log server verifies, then reverses steps 5, 4, 3 and logs the unlock as its own event.

**Known limitation to state honestly:** an attacker who already has root could try to kill the break-glass controller before it fires. The witness detects this through missed heartbeats, and the vault already holds everything streamed up to that point.

**Module**: `layers/l3_breakglass/`

## Witness: no SSH

- Witness image does not install `openssh-server` at all.
- Only the heartbeat/challenge API port is exposed.
- Demo moment: from the `attacker` container, show that port 22 on the witness is closed.

## Dashboard additions

**SOC view**
- Live timeline of layer events, color-coded by layer
- Current system state: normal / alert / FROZEN
- Panic button (Layer 3 manual trigger)

**Auditor view**
- List of evidence bundles from the vault, with verification status (signature valid, hash matches witness)
- For each incident: before, after, diff, and who
- Break-glass unlock panel (enter shares)

## Suggested folder layout

Adapt to the existing v2 structure after reading it.

```
layers/
  common/
    events.py
    evidence.py
  l1_tripwire/
    wrappers/          # nano, vim, rm, ...
    shell_profile.sh   # cd function, PATH order
    audit.rules
    unlock.py          # coc-unlock
    commands/          # coc-view, coc-status, coc-verify
  l2_hooks/
    hooks.py
  l3_breakglass/
    triggers.py
    controller.py      # capture, push, isolate, freeze, lock
    shamir_unlock.py
docker/
  docker-compose.yml
  log-server/Dockerfile
  witness/Dockerfile
  vault/               # MinIO setup + bucket/object-lock init script
  attacker/Dockerfile
docs/
  integration_map.md
  phase0_results.md
  demo_script.md
tests/
```

## Build order

Order: **Layer 2 → Layer 1 → Layer 3** (details in `02-flow.md`).

1. **Layer 2, natively, before Round 1:** fake bank stub, Checks A to C (heartbeat + checksums), tamper classifier, terminal watcher. Phase 0 kernel spike in parallel (3rd member)
2. Docker compose with all five containers running (after Round 1)
3. **Layer 2, continued:** evidence bundles + vault
4. **Layer 1:** wrappers + team commands, auditd backstop feeding Layer 2
5. **Layer 3:** break glass + Shamir unlock
6. Dashboard additions
7. Demo script and full run-through, integration map

Steps 1 to 3 alone are already a demoable story, so if time runs short, the project still has a working story.

## Demo script outline (write the full version in `docs/demo_script.md`)

1. Normal operation: logs streaming, heartbeats green
2. Attacker gets in with stolen admin credentials, types `nano app.log`: **Layer 1 trips**, bundle appears in auditor view
3. Attacker bypasses with `/usr/bin/nano` and edits a record: **auditd backstop + Layer 2** catch it, auditor view shows before / after / diff / who
4. Attacker tries to delete the evidence in the vault: denied by object lock
5. Attacker locks the admin out: **Layer 3 fires**, system freezes, attacker's session is killed too
6. Two key holders enter shares in the dashboard: system unlocks, every step is in the evidence trail
7. Show the witness has no SSH

## Tests to include

- Each wrapper fires an event and blocks the real command
- Full-path execution is still caught by auditd (or fallback)
- Editor temp-file + rename save is caught
- Log server credential cannot read or delete vault objects
- Evidence bundle signature verifies; a modified bundle fails verification
- Break glass runs steps in order and reaches FROZEN
- Unlock fails with one share, succeeds with any two
- Witness port 22 is closed
