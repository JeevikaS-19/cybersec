# 07 · Attack List (for the 3rd member)

Build these as standalone scripts in `attacks/`, one file per attack: `a1_edit_entry.py`, `a2_delete_middle.py`, etc. Each script should print what it did and what alert it expects, so it doubles as the demo script.

Each targets a running system (`victim/` + `agent/` + `witness/`, and `feed/` once built). Most work by editing the SQLite file directly or stopping a process — you don't need witness/agent internals to write these. For local-vs-witness comparisons (A3, A7, T2d), run `attacks/compare_local.py`: it reads the agent's local SQLite, posts the entries to the witness's `POST /verify/compare` (available from Step 4, see `06-api-contract.md`) and prints the mismatches.

| # | Attack | How | Expected | Caught by (layer) | Matching self-test |
|---|---|---|---|---|---|
| A1 | Edit a stored entry | Open witness's SQLite, change one field in a stored entry | Periodic self-check hash mismatch at that entry (Layer 1 red, live within 5 s, no new entry needed) | 1 | T1b |
| A2 | Delete entries from the middle | Delete a row from witness's SQLite | Sequence gap (periodic self-check, within 5 s) | 1 | T1c |
| A3 | Truncate the latest entries | Delete the last few rows from the **agent's local** copy | Witness still has them; `/verify/compare` reports `missing_locally` | 2 | T2d |
| A4 | Kill / block the agent | Stop the agent process, or disconnect Laptop A from hotspot | Silence alert within 15s | 2 | T2a / T2b |
| A5 | Backdate a timestamp | Insert an entry with an old timestamp between two recent ones | Non-monotonic timestamp alert (not a "far from now" check — see `06-api-contract.md`) | 1 | T2c |
| A6 | Change an amount only | Edit `amount_paise` in a stored entry | Chain break + balance mismatch on the affected account | 1, 3 | T1b, T3a |
| A7 | Rewrite the whole local chain | Regenerate the agent's local chain from scratch with new (consistent) fake data | Witness's stored copy disagrees via `/verify/compare` (`hash_mismatch`) | 2 | T2d |
| A9 | Steal current key, forge old entries | Use the agent's current private key to re-sign an old entry | Signature doesn't match the key that was valid for that time range | 1 | T4a |
| A10 | Compromised witness rewrites history | Same mechanics as A1, but assume the attacker also controls the witness (so its self-check can be silenced) | Receipt and anchor mismatch: external to the witness, survives a fully compromised witness | 2, 3 | T4b |
| A11 | Stop logging / tamper with config | Kill the agent right after editing its config | Config-stop event was logged before it died | 2 | (Step 8, if built) |
| **A12** | **Edit DB balance directly, no log entry** | **Open `victim/`'s SQLite, change a balance, write no entry** | **Layers 1–2 stay green; state challenge mismatch (Check 2)** | **3 only** | **T3b** |
| **A13** | **Fabricated transaction via compromised agent** | **Make the agent emit an entry for a transfer that never happened in `victim/`** | **No matching feed confirmation (Check 3)** | **3 only** | **T3c** |
| **A14** | **Redirect: same amount, different destination** | **Edit `to_account` on an entry before it's sent, keep the amount the same** | **Feed confirms the real account; mismatch (Check 3)** | **3 only** | **T3d** |

**Note on A13/A14 and the demo feed:** in the live demo, the feed is fed over a side channel from the bank (see `02-flow.md` Step 8's "demo simplification"). For A13/A14 to demonstrate the real mechanism, run the fake/redirected transaction through the **agent only**, not through that side channel — the feed must genuinely not hear about it for the mismatch to be real, not staged.

## Build order for the 3rd member
1. A1, A2, A4, A12 — needed for Round 1 (`02-flow.md` Steps 1–7).
2. A13, A14 — needed once `feed/` exists (Step 8).
3. A5, A6, A9, A10 — needed for Round 2.
4. A3, A7, A11 — nice to have, only if time allows. Write `compare_local.py` first; A3 and A7 depend on it.

**A1 vs A10:** same action (edit the witness DB), different claim. A1 shows the live self-check catching it within 5 s. A10 assumes the witness itself is compromised, so only the agent's receipts and the off-box anchor on Laptop C can prove the rewrite.

**Slide-only, not built:** A8 (turn off checks in local profile). It depends on a profile system that's slide-only this event.

## Demo script
Pulls from `03-pitch-demo.md`'s demo order: A1 → A4 → A12 → A13. Keep a recording of a clean run of this exact sequence as backup.
