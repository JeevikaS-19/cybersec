import requests

from shared import canonical_encode, generate_keypair, hash_entry, sign_payload
from tests.helpers import Agent, ts
from witness import checks
from witness.store import connect


def _alerts(db):
    conn = connect(db)
    try:
        return [(r["kind"], r["ref"], r["tamper_type"]) for r in conn.execute("SELECT kind, ref, tamper_type FROM alerts ORDER BY id")]
    finally:
        conn.close()


def _run(db, sql=None):
    conn = connect(db)
    try:
        if sql:
            with conn:
                conn.execute(sql)
        checks.self_check(conn, checks.now())
        checks.self_check(conn, checks.now())
    finally:
        conn.close()


def test_t1a_same_entry_same_bytes_and_hash():
    entry = {"seq": 1, "timestamp": ts(1), "event_type": "transaction", "txn_id": "txn-00001",
             "from_account": "acc-1", "to_account": "acc-2", "amount_paise": 100,
             "from_balance_paise": 1000, "to_balance_paise": 2000, "prev_hash": "x", "key_id": "agent-key-0"}
    entry["hash"] = hash_entry(entry)
    again = dict(entry)
    assert canonical_encode(entry) == canonical_encode(again)
    assert hash_entry(entry) == hash_entry(again) == entry["hash"]


def test_t1b_edited_stored_entry_flags_exactly_once(witness):
    a = Agent(witness.url)
    for _ in range(3):
        assert a.send(a.next_entry())["status"] == "accepted"
    _run(witness.db, "UPDATE entries SET amount_paise = amount_paise + 1 WHERE seq = 2")
    assert _alerts(witness.db) == [("entry_edited", "2", "entry_edited")]


def test_t1c_deleted_middle_entry_flags_sequence_gap(witness):
    a = Agent(witness.url)
    for _ in range(3):
        a.send(a.next_entry())
    _run(witness.db, "DELETE FROM entries WHERE seq = 2")
    assert _alerts(witness.db) == [("entry_deleted", "2", "entry_deleted")]


def test_t1d_swapped_entries_are_sequence_error(witness):
    a = Agent(witness.url)
    first = a.next_entry()
    second = a.next_entry()
    third = a.next_entry()
    assert a.send(first)["status"] == "accepted"
    assert a.send(third) == {"status": "rejected", "reason": "sequence_gap"}
    assert a.send(second)["status"] == "accepted"
    assert ("sequence_gap", "3", "entry_deleted") in _alerts(witness.db)
    # The agent resends seq 3 after seq 2 is in: that rejected entry is now accepted late.
    assert a.send(third)["status"] == "accepted"
    assert ("late_entry", "3", "entries_reordered") in _alerts(witness.db)


def test_t1d_wrong_prev_hash_is_chain_break(witness):
    a = Agent(witness.url)
    a.send(a.next_entry())
    bad = a.make(2, "not-the-real-hash", ts(2))
    assert a.send(bad) == {"status": "rejected", "reason": "chain_break"}
    assert ("chain_break", "2", "entry_inserted") in _alerts(witness.db)


def test_t1e_entry_signed_with_other_key_is_bad_signature(witness):
    a = Agent(witness.url)
    a.send(a.next_entry())
    other, _ = generate_keypair()
    forged = a.make(2, a.chain[0]["hash"], ts(2), priv=other)
    assert a.send(forged) == {"status": "rejected", "reason": "bad_signature"}
    assert _alerts(witness.db) == [("bad_signature", "2", "forged")]


def test_t1f_replayed_entry_is_sequence_error(witness):
    a = Agent(witness.url)
    first = a.next_entry()
    a.send(first)
    a.send(a.next_entry())
    assert a.send(first) == {"status": "rejected", "reason": "sequence_gap"}  # an older entry sent again
    assert _alerts(witness.db) == [("sequence_gap", "1", "entry_replayed")]


def test_t1g_one_bad_entry_does_not_cascade(witness):
    a = Agent(witness.url)
    a.send(a.next_entry())
    other, _ = generate_keypair()
    bad = a.make(2, a.chain[0]["hash"], ts(2), priv=other)
    assert a.send(bad)["status"] == "rejected"
    for _ in range(5):
        assert a.send(a.next_entry())["status"] == "accepted"
    assert _alerts(witness.db) == [("bad_signature", "2", "forged")]
    _run(witness.db)
    assert _alerts(witness.db) == [("bad_signature", "2", "forged")]


def test_swapped_stored_rows_are_entries_reordered(witness):
    a = Agent(witness.url)
    for _ in range(3):
        a.send(a.next_entry())
    conn = connect(witness.db)
    try:
        with conn:
            id2, id3 = [r["id"] for r in conn.execute("SELECT id FROM entries WHERE seq IN (2, 3) ORDER BY seq")]
            # Swap the insertion order of the stored rows for seq 2 and seq 3.
            conn.execute("UPDATE entries SET id = -1 WHERE id = ?", (id2,))
            conn.execute("UPDATE entries SET id = ? WHERE id = ?", (id2, id3))
            conn.execute("UPDATE entries SET id = ? WHERE id = -1", (id3,))
    finally:
        conn.close()
    _run(witness.db)
    kinds = {(k, ref) for k, ref, _ in _alerts(witness.db)}
    assert ("entries_reordered", "2") in kinds
    assert not any(k == "entry_deleted" for k, _ in kinds)  # a swap is not a deletion


RECORD_FIELDS = ("txn_id", "timestamp", "from_account", "to_account", "amount_paise",
                 "from_balance_paise", "to_balance_paise")


def _poll(a):
    return requests.get(f"{a.url}/challenge/poll", params={"platform_id": a.platform_id}, timeout=5).json()["challenge"]


def _reply(a, payload):
    payload["signature"] = sign_payload(a.priv, dict(payload))
    return requests.post(f"{a.url}/challenge/response", json=payload, timeout=5).json()


def _server(a, seq, **changes):
    rec = {f: a.chain[seq - 1][f] for f in RECORD_FIELDS}
    rec.update(changes)
    return rec


def test_record_check_catches_server_side_edit_then_full_sweep_lists_all(witness, monkeypatch):
    from witness import records

    a = Agent(witness.url)
    for _ in range(5):
        a.send(a.next_entry())
    monkeypatch.setattr(checks, "CHALLENGE_CHANCE", 1.0)
    monkeypatch.setattr(checks, "STATE_SHARE", 0.0)
    monkeypatch.setattr(checks, "RECORD_SHARE", 1.0)
    monkeypatch.setattr(records, "SWEEP_SECONDS", float("inf"))
    ch = _poll(a)
    assert ch["type"] == "record"
    seq = ch["seq"]
    # Attacker edited the bank's row for this record: amount cut to 1 paise.
    body = {"challenge_id": ch["id"], "type": "record", "seq": seq, "record": _server(a, seq, amount_paise=1)}
    assert _reply(a, body) == {"status": "mismatch"}
    status = requests.get(f"{witness.url}/status", timeout=5).json()
    assert status["checks"]["A"] == "red"
    (m,) = requests.get(f"{witness.url}/mismatches", timeout=5).json()["mismatches"]
    assert m["seq"] == seq and m["fields"] == ["amount_paise"]
    assert m["witness_copy"]["amount_paise"] == 100 and m["server_copy"]["amount_paise"] == 1
    assert m["witness_hash"] != m["server_hash"]
    # Next challenge is a full sweep; a second tampered record and a deleted one get listed too.
    sweep = _poll(a)
    assert sweep["type"] == "sweep" and sweep["seqs"] == [1, 2, 3, 4, 5]
    other = 1 if seq != 1 else 2
    gone = 5 if seq != 5 else 4
    recs = [{"seq": s, "record": None if s == gone else _server(a, s, **({"amount_paise": 1} if s in (seq, other) else {}))}
            for s in sweep["seqs"]]
    assert _reply(a, {"challenge_id": sweep["id"], "type": "sweep", "records": recs}) == {"status": "mismatch"}
    found = {m["seq"]: m for m in requests.get(f"{witness.url}/mismatches", timeout=5).json()["mismatches"]}
    assert set(found) == {seq, other, gone}
    assert found[gone]["server_copy"] is None
    tamper = {(x["kind"], x["ref"]): x["tamper_type"] for x in requests.get(f"{witness.url}/alerts", timeout=5).json()["alerts"]}
    assert tamper[("record_mismatch", str(gone))] == "entry_deleted"


def test_honest_sweep_matches_and_stays_green(witness, monkeypatch):
    from witness import records

    a = Agent(witness.url)
    for _ in range(3):
        a.send(a.next_entry())
    monkeypatch.setattr(records, "SWEEP_SECONDS", 0)
    sweep = _poll(a)
    assert sweep["type"] == "sweep"
    recs = [{"seq": s, "record": _server(a, s)} for s in sweep["seqs"]]
    assert _reply(a, {"challenge_id": sweep["id"], "type": "sweep", "records": recs}) == {"status": "ok"}
    assert requests.get(f"{witness.url}/mismatches", timeout=5).json()["mismatches"] == []
    assert requests.get(f"{witness.url}/status", timeout=5).json()["checks"]["A"] == "green"


def test_identical_resend_after_lost_reply_is_accepted_once(witness):
    a = Agent(witness.url)
    first = a.next_entry()
    a.send(first)
    assert a.send(first) == {"status": "accepted"}  # same seq, same hash, same signature
    a.send(a.next_entry())
    assert _alerts(witness.db) == []
