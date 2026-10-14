# 00 · Pre-Event Checklist

Hackurity 2026 · PS-6 Chain of Custody · Firewall Crew

## Event times
| When | What |
|---|---|
| Day 1, 8:00 AM | Build starts |
| Day 1, 3:00 to 4:00 PM | **Round 1** (pitch + skeleton demo) |
| Day 1, 7:30 to 8:30 PM | **Round 2** (working demo) |
| Day 2, 10:00 AM | **Final** (product demo + full pitch) |

## Files in this pack
| File | What it's for |
|---|---|
| `LAYERS_PLAN.md` | The v3 design: vault, Layers 1 to 3, Docker setup |
| `01-rules.md` | How Antigravity, Claude Code and the team work together |
| `02-flow.md` | Build order, owners, what each piece does technically |
| `03-pitch-demo.md` | Pitch and demo for each round |
| `04-token-saver.md` | Rules so the AI doesn't waste tokens |
| `05-self-tests.md` | Tests we run ourselves |
| `06-api-contract.md` | Routes, request bodies and signed fields between containers |
| `07-attacks.md` | Attack scripts list, for the 3rd member |
| `08-fixes-changelog.md`, `09-fix` | History of fixes (09 is superseded by v3) |

## Before the event
**Team**
- [ ] All 3 have read `LAYERS_PLAN.md`, `02-flow.md` and `06-api-contract.md`, and agree on the entry format and routes
- [ ] Owners confirmed (table in `02-flow.md`)
- [ ] Confirm the rules allow feeding pre-written docs to AI tools
- [ ] Check whether the judging rubric is published

**Laptop (demo machine) and Docker**
- [ ] Docker Desktop installed, WSL2 backend on, `docker compose version` works
- [ ] Base images pulled before the event (installing is not coding): `python:3.11-slim`, `minio/minio`, `minio/mc`, an `ubuntu`/`debian` image for `log-server` and `attacker`
- [ ] Docker Desktop memory set to at least 4 GB
- [ ] Quick manual check (no code): `docker run --rm --cap-add AUDIT_CONTROL --cap-add NET_ADMIN --cap-add LINUX_IMMUTABLE debian` starts, so Phase 0 has a chance
- [ ] Python, `cryptography`, `pycryptodome`, `minio`, `pyyaml`, `pytest`, `ruff` installed locally for tests
- [ ] Other two laptops: Antigravity and Claude Code work; they clone the repo and push branches
- [ ] Phone hotspot (AI tools only) + backup hotspot; check data balance

**AI setup**
- [ ] `01-rules.md` and `04-token-saver.md` copied into `AGENTS.md` (Antigravity) and `CLAUDE.md` (Claude Code)
- [ ] Both Claude Code accounts logged in, Antigravity logged in

**Pitch**
- [ ] Round 1 slides drafted (`03-pitch-demo.md`)
- [ ] Architecture diagram drawn (5 containers, Checks A to C, Layers 1 to 3, vault)
- [ ] Judge questions rehearsed once

**Personal**
- [ ] Prep time blocked separately from HACKFEST Round 1 (due Oct 18)
- [ ] Sleep shifts agreed for the night
