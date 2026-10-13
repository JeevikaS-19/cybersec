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
| `01-rules.md` | How Antigravity, Claude Code and the team work together |
| `02-flow.md` | Build order + what each piece does technically |
| `03-pitch-demo.md` | Pitch and demo for each round |
| `04-token-saver.md` | Rules so the AI doesn't waste tokens |
| `05-self-tests.md` | Tests we run ourselves before the red team is ready |
| `06-api-contract.md` | Routes and request bodies between the 3 laptops |
| `07-attacks.md` | Attack scripts list, for the 3rd member |
| `08-fixes-changelog.md`, `09-fix` | History of fixes (09 applied to 02, 03, 05, 06, 07) |

## Before the event
**Team**
- [ ] All 3 have read `02-flow.md` and `06-api-contract.md`, and agree on the entry format (Step 1) and routes
- [ ] Roles confirmed: Jeev = `shared/`, `agent/`, `witness/`, crypto · Jaganath = `victim/`, `dashboard/` · 3rd member = `feed/`, `attacks/`
- [ ] Confirm the rules allow feeding pre-written docs to AI tools
- [ ] Check whether the judging rubric is published

**Laptops and network**
- [ ] Laptop A = platform + agent, Laptop B = witness + dashboard, Laptop C = feed + red team
- [ ] Python, FastAPI, Streamlit (or plain HTML), `cryptography`, `pytest`, `ruff` installed on all 3 **before** the event (installing is not coding)
- [ ] All 3 laptops join one phone hotspot and can reach each other (ping test)
- [ ] Windows Firewall: allow the witness port on Laptop B (default blocks inbound). Laptop A and C need no inbound rule — they only poll out (see `06-api-contract.md`)
- [ ] Second phone ready as backup hotspot
- [ ] Check data balance on both phones (AI tools use hotspot data)

**AI setup**
- [ ] `01-rules.md` and `04-token-saver.md` copied into `AGENTS.md` (Antigravity) and `CLAUDE.md` (Claude Code)
- [ ] Both Claude Code accounts logged in, Antigravity logged in

**Pitch**
- [ ] Round 1 slides drafted (`03-pitch-demo.md`)
- [ ] Architecture diagram drawn
- [ ] Judge questions rehearsed once, including the feed-shortcut question

**Personal**
- [ ] Prep time blocked separately from HACKFEST Round 1 (due Oct 18)
- [ ] Sleep shifts agreed for the night