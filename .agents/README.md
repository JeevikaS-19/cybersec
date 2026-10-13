# Antigravity setup

| Path | Does |
|---|---|
| `../AGENTS.md` | Working rules + token saver (copied from `MD_FILES/01` and `04`). Re-copy if those change. |
| `rules/00-project.md` | Always on: points to `AGENTS.md` and the current step |
| `rules/10-crypto-and-verification.md` | Auto for `agent/`, `witness/`, `feed/`: encoding, signing, witness rules |
| `workflows/step.md` | `/step 3`: plan, wait, build, explain, hand the review line to Claude |

**Loop:** `/step N` → OK the plan → Gemini builds → paste its review line into Claude Code → PASS: commit; FAIL: paste the error back to Gemini.

**Check before the event:** open the repo root in Antigravity; Customizations should list 2 rules and 1 workflow. `/step 1` must print a plan and stop. If it writes code, rules didn't load (if your version only reads `.agent/`, rename the folder).
