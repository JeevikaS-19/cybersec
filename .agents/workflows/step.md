---
description: Start one build step from MD_FILES/02-flow.md. Usage /step 3
---

1. Read only `### Step <N>` in `MD_FILES/02-flow.md` and the routes it uses in `MD_FILES/06-api-contract.md` (06 wins if they differ). Check you own that step's folder (AGENTS.md, Team rules). If not, stop and say who owns it.
2. Reply with a plan, max 5 lines: files you will touch, what you will add, the self-tests from `MD_FILES/05-self-tests.md` it must pass. No code.
3. Wait for the human's OK.
4. Write the code for this step only. If it grows past ~100 lines, stop and propose a split.
5. Explain what the code does in max 5 lines.
6. Print this line for the human to paste into Claude Code, then stop:
   `Review the diff for Step <N> against MD_FILES/02-flow.md and 06-api-contract.md. Run tests <IDs>. Files: <list>.`
