import pytest

from witness.classify import TAMPER_TYPES, for_rejection
from witness.store import add_alert, connect, init_db


@pytest.mark.parametrize(
    "reason, seq, last_seq, expected",
    [
        ("bad_signature", 2, 1, "forged"),
        ("unknown_key_id", 2, 1, "forged"),
        ("chain_break", 2, 1, "entry_inserted"),
        ("non_monotonic_timestamp", 3, 2, "backdated"),
        ("sequence_gap", 3, 1, "entry_deleted"),  # ahead of expected: a gap
        ("sequence_gap", 1, 1, "entry_replayed"),  # same seq again
        ("sequence_gap", 0, 1, "entry_replayed"),
    ],
)
def test_rejection_reasons_map_to_tamper_types(reason, seq, last_seq, expected):
    assert for_rejection(reason, seq, last_seq) == expected
    assert expected in TAMPER_TYPES


def test_unknown_tamper_type_is_stored_with_warning(tmp_path, capsys):
    db = str(tmp_path / "witness.db")
    init_db(db)
    conn = connect(db)
    try:
        add_alert(conn, "made_up", "1", "not_a_tamper_type", "", 0.0)
        row = conn.execute("SELECT tamper_type FROM alerts WHERE kind = 'made_up'").fetchone()
    finally:
        conn.close()
    assert row["tamper_type"] == "not_a_tamper_type"
    assert "WARNING" in capsys.readouterr().out
