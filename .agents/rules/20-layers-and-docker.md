---
trigger: glob
globs: layers/**, docker/**, config/**
---

# Response layers and Docker (Layers 1 to 3, vault, containers)

- Design: `MD_FILES/LAYERS_PLAN.md`. Build order: Layer 2 (heartbeat + checksum, Checks A to C, tamper classifier) → Layer 1 (tripwire) → Layer 3 (break glass). Checks A to C are parts of Layer 2.
- New layer code goes in new modules under `layers/`. Base modules get only the smallest hook, and you say what you changed.
- Every layer is switchable in `config/layers.yaml`.
- Every layer emits events through `layers/common/events.py` and evidence through `layers/common/evidence.py`. No second event format.
- Layer 1: wrappers detect and block; auditd (execve rules + `-p wa` on the log **directory**) is the real enforcement. Fallback: inotify + process lookup. Team access = `<cmd> --<profile-id>` checked against a stored hash, logged, no alert. Guarded commands and paths come from `config/layers.yaml`, never hardcoded.
- Layer 2: every alert gets a `tamper_type` from `witness/classify.py` (values in `06-api-contract.md`). When Layer 1's auditd is added, feed its file-write events into Layer 2 so direct edits flag immediately with who did it.
- Layer 3 order is fixed: capture → push bundle → isolate (iptables DROP except vault + witness) → freeze (`chattr +i` or read-only remount) → lock out → report FROZEN. **No reboot anywhere.** Unlock = Shamir 2-of-3 via the witness's signed command; log-server stores only `sha256(secret)`; reverse 5, 4, 3 and log it.
- Vault: MinIO, object lock in compliance mode, versioning on. log-server credential = `s3:PutObject` only; auditor credential = read only. Credentials come from compose env vars, never hard-coded or committed.
- Witness image: no `openssh-server`; publish only the API port.
- Phase 0 results (`docs/phase0_results.md`) decide fallbacks. Don't fight a kernel feature longer than 45 minutes.
- Leave the network-cut local buffer as a `TODO` stub only.
