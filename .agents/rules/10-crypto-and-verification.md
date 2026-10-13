---
trigger: glob
globs: shared/**, agent/**, witness/**, feed/**
---

# Crypto and verification (Layers 1 to 3 depend on this)

- Fields, routes and the exact signed-field lists: `MD_FILES/06-api-contract.md` ("What gets signed"). Never rename or add fields without asking.
- Encoding, hashing and `GENESIS_PREV_HASH` (base64 of 32 zero bytes) live only in `shared/`, imported by agent and witness. Canonical = `json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")`. `hash` covers every field except `hash` and `signature`. Floats raise an error.
- Keys, hashes and signatures are base64 of raw bytes.
- Private keys never printed, logged, sent, or leave their laptop. Witness holds public keys only, as a growing `key_id -> public_key` map per platform. Unknown `key_id` = rejection `unknown_key_id`, never a crash.
- Agent: no balance or reconciliation logic; reports `from_balance_paise` / `to_balance_paise` as the bank DB says. Keeps a local SQLite copy of every entry. If sending fails, queue and resend with the SAME seq. Heartbeat every 5 s, signed over `{platform_id, timestamp}`.
- Witness validates each entry against `last_good_seq` / `last_good_hash` (accepted entries only). Rejected entries are stored, raise exactly one alert, and never become the reference. Never UPDATE or DELETE stored entries.
- Timestamp check = later than the last accepted entry (monotonic), NOT "close to now". Liveness = no valid heartbeat for 15 s; a heartbeat counts only if signed and newer than the last one.
- Self-check every 5 s over accepted entries: recompute hashes, check links and seq. One alert per broken entry (de-duplicated).
- Witness never trusts the agent's balances or challenge replies on their own; its replay is the truth. Feed matching: `txn_id`, accounts, amount, 30 s either side.
- Wording: tampering is "detected", never "impossible".
