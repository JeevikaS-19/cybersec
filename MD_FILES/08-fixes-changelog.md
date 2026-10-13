# 08 · Fixes applied (changelog against the pack you flagged)

1. **No API contract** → `06-api-contract.md` added. Agent and feed poll the witness (no inbound rule needed on Laptops A/C). Used by `02-flow.md` and `07-attacks.md`.
2. **Ambiguous `running_balance_paise`** → split into `from_balance_paise` and `to_balance_paise` everywhere (shared encoding, entries, Check 1 replay, T3a).
3. **No `shared/` folder** → added, owned by Jeev, holds canonical encoding/hashing, imported by `agent/` and `witness/`. Written in Step 1.
4. **No registration step** → `POST /register/agent` and `POST /register/feed` defined in `06-api-contract.md`, called at agent/feed startup in Step 0; witness refuses unregistered keys.
5. **Retries vs. timestamp check clash** → Step 4's check changed from "close to wall-clock now" to "monotonically later than the previous stored entry." Freshness/liveness is the separate heartbeat-silence check. `06-api-contract.md`'s `non_monotonic_timestamp` reason documents this. T2b and T2c in `05-self-tests.md` updated to test this directly.
6. **T0 would take 2.8 hours** → fast mode added to the bank generator (Step 2), used only for T0; normal 1/sec mode kept for live demos.
7. **T2d had nothing to run against** → witness's `GET /verify` endpoint moved up to be available from Step 4 (core logic), with the Step 12 auditor tab as just its UI. `attacks/` and self-tests use it directly from Step 4 on.
8. **Feed demo shortcut undercuts "settlement never confirmed it"** → named explicitly as a demo simplification in `02-flow.md` Step 8, `03-pitch-demo.md`'s honest-limits slide, and a rehearsed judge question. `07-attacks.md` notes A13/A14 must bypass the shortcut to demo the real mechanism.
9. **pytest/ruff allowed?** → confirmed, added to the allowed list in `01-rules.md` explicitly as dev-only tools.
10. **05 referenced attacks with no list** → `07-attacks.md` created; `05-self-tests.md`'s handover table now points to it.
