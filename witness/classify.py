"""Tamper classifier: every alert carries one tamper_type (06-api-contract.md)."""

TAMPER_TYPES = frozenset({
    "entry_edited", "entry_deleted", "entries_reordered", "entry_replayed", "entry_inserted",
    "backdated", "forged", "agent_silenced", "balance_misreported", "db_edited_without_log",
    "l1_bypass",
})

_BY_REASON = {
    "bad_signature": "forged",
    "unknown_key_id": "forged",
    "chain_break": "entry_inserted",
    "non_monotonic_timestamp": "backdated",
    "malformed_entry": "forged",
}


def for_rejection(reason, seq, last_seq):
    # A seq at or below the last accepted one is a replay; a seq ahead of the expected one is a gap.
    if reason == "sequence_gap":
        return "entry_replayed" if isinstance(seq, int) and seq <= last_seq else "entry_deleted"
    return _BY_REASON[reason]
