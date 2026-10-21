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


def test_t9b_edited_amount_paise_detail_names_the_field(witness):
    """T9b: edit amount_paise of a stored entry; /alerts must name the field and old/new values."""
    import requests

    from tests.helpers import Agent
    from witness import checks
    from witness.store import connect

    a = Agent(witness.url)
    for _ in range(3):
        assert a.send(a.next_entry())["status"] == "accepted"

    # Attacker edits the bank's stored row for seq=2 directly in the witness DB.
    conn = connect(witness.db)
    try:
        with conn:
            conn.execute("UPDATE entries SET amount_paise = 200 WHERE seq = 2")
        checks.self_check(conn, checks.now())
    finally:
        conn.close()

    alerts = requests.get(f"{witness.url}/alerts", timeout=5).json()["alerts"]
    edited = [a for a in alerts if a["kind"] == "entry_edited"]
    assert len(edited) == 1, f"expected 1 entry_edited alert, got {edited}"
    assert edited[0]["tamper_type"] == "entry_edited"
    detail = edited[0]["detail"]
    assert "amount_paise" in detail, f"detail missing field name: {detail!r}"
    assert "100" in detail, f"detail missing old value 100: {detail!r}"
    assert "200" in detail, f"detail missing new value 200: {detail!r}"
