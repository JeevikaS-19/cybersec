---
trigger: glob
globs: shared/**, agent/**, witness/**, layers/common/**
---

# Base checks and crypto (Checks A to C, evidence signing)

- Fields, routes and the exact signed-field lists: `MD_FILES/06-api-contract.md` ("What gets signed"). Never rename or add fields without asking.
- Encoding, hashing, signing and `GENESIS_PREV_HASH` (base64 of 32 zero bytes) live only in `shared/`. Canonical = `json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")`. `hash` covers every field except `hash` and `signature`. Floats raise an error.
- Keys, hashes and signatures are base64 of raw bytes.
- Private keys never printed, logged, sent or committed. Witness holds public keys only (plus its own command-signing key), as a `key_id -> public_key` map. Unknown `key_id` = rejection `unknown_key_id`, never a crash.
- Agent: no balance logic; reports `from_balance_paise` / `to_balance_paise` from the bank DB. Keeps a local SQLite copy. Queue and resend with the SAME seq on failure. Signed heartbeat every 5 s.
- Witness validates against `last_good_seq` / `last_good_hash` only. Rejected entries are stored, alert once, never become the reference. Never UPDATE or DELETE stored entries.
- Timestamp check = monotonic vs last accepted entry, NOT "close to now". Silence = no valid (signed, newer) heartbeat for 15 s.
- Self-check every 5 s re-hashes accepted entries; one alert per broken entry.
- Witness never trusts the agent's balances or challenge replies on their own.
- Evidence bundles: built and signed in `layers/common/evidence.py`, pushed to the vault with the PutObject-only credential, bundle hash sent via `POST /events`.
- Wording: tampering is "detected", never "impossible".
