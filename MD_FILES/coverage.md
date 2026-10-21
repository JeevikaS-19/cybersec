# Detection coverage

Red-team scenarios run against the chain-of-custody witness. One row per scenario.
Filled by Bob in Red Team mode after each batch. Attacker holds ct105, not the
witness host or key history (see MD_FILES/redteam-brief.md).

## Results

| ID | Layer | What it changes | Expected | Caught? | Which check caught it | Alert fired | Time to detect |
|----|-------|-----------------|----------|---------|-----------------------|-------------|----------------|
| L1-01 | 1 | _e.g. in-place edit of watched log_ | caught | | | | |
| L2-01 | 2 | _e.g. amount +1.00 on a committed row_ | caught | | | | |
| L3-01 | 3 | _e.g. network cut 100 s_ | caught | | | | |
| T9b | 2 | `amount_paise` of a stored witness entry edited (100 → 200) after acceptance | caught | ✅ | Check A — `self_check()` re-hashes every stored row | `entry_edited` alert; `tamper_type: entry_edited`; detail: `"amount_paise: 100 → 200"` | Immediate (next `self_check` poll cycle) |
| T6a | 1 | Attacker uses `/usr/bin/nano app.log` (full-path bypass of wrapper); backstop catches the file access via inotify + `/proc` attribution | caught | ✅ | Layer 1 backstop (`backstop:write` event → `POST /events` → `layer1_tripwire` alert) | `layer1_tripwire` alert; `tamper_type: l1_bypass`; detail includes cmd, target, suspects | Immediate (next backstop inotify event + agent spool flush) |
| T5c | 1 | Attacker creates a temp file with forged content and renames it over the real log (`mv /tmp/fake.log /var/log/bank/app.log`) | caught | ✅ | Layer 1 wrapper — `mv` is a guarded `file_command`; deception mode fires `wrapper:mv` alert and returns 0 (real file untouched); block mode returns 1 | `wrapper:mv` event; `state: alert`; detail contains cmd and target path | Immediate (wrapper intercepts before the rename runs) |
| T7a | 3 | Agent goes silent (network cut); silence detected at 15 s; quarantine presumed at 45 s | caught | ✅ | Check B `silence_check()` → `silence` alert at 15 s; `quarantine.presume()` flips state at 45 s | `silence` alert (`tamper_type: agent_silenced`); then `state: quarantined`; server reports, stays locked until 2-of-3 unlock | `SILENCE_SECONDS` = 15 s for alert; `after_seconds` = 45 s for quarantine |

## Misses (close these before the demo)

| ID | Layer | Why it slipped through (hypothesis) | Kind of fix |
|----|-------|-------------------------------------|-------------|

## Honest boundary

Scenarios that are out of scope because root on ct105 can defeat them by design
(forging events, lying through the bank API). List them so the demo names them
openly rather than being caught out.

-
