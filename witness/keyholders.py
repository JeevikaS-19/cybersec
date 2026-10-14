"""Layer 3 unlock secret, split 2-of-3 (Shamir) between the key holders.

    python -m witness.keyholders init DB_PATH OUT_DIR "SOC lead" "Auditor" "Compliance officer"

writes one share file per holder into OUT_DIR (hand them out, then delete them) and stores only
sha256(secret) in the witness. The log server gets the same hash at registration and unlocks only when an
unlock command carries a secret that matches it: a compromised witness can't unlock without 2 holders.
Shares and the secret are never printed or logged.
"""

import hashlib
import os
import re
import secrets
import sys
from pathlib import Path

from witness.store import connect, get_state, init_db, set_state

SHARE = re.compile(r"^([1-9])-([0-9a-f]{32})$")


def secret_hash(conn):
    return get_state(conn, "unlock_secret_hash")


def init(db_path, out_dir, holders, needed=2):
    from Crypto.Protocol.SecretSharing import Shamir
    init_db(db_path)
    secret = secrets.token_bytes(16)
    shares = Shamir.split(needed, len(holders), secret)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for (idx, share), name in zip(shares, holders, strict=True):
        path = out / (re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") + ".share")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{idx}-{share.hex()}\n")
    conn = connect(db_path)
    try:
        set_state(conn, "unlock_secret_hash", hashlib.sha256(secret).hexdigest())
        set_state(conn, "key_holders", list(holders))
    finally:
        conn.close()
    return out


def valid_format(share):
    return isinstance(share, str) and bool(SHARE.match(share.strip().lower()))


def combine(shares, expected_hash):
    """The secret if these shares rebuild it, else None."""
    from Crypto.Protocol.SecretSharing import Shamir
    parsed = []
    for s in shares:
        m = SHARE.match(s.strip().lower())
        if not m:
            return None
        parsed.append((int(m.group(1)), bytes.fromhex(m.group(2))))
    if len({i for i, _ in parsed}) != len(parsed):
        return None
    try:
        secret = Shamir.combine(parsed)
    except ValueError:
        return None
    return secret if hashlib.sha256(secret).hexdigest() == expected_hash else None


if __name__ == "__main__":
    if len(sys.argv) >= 5 and sys.argv[1] == "init":
        where = init(sys.argv[2], sys.argv[3], sys.argv[4:])
        print(f"{len(sys.argv) - 4} share files written to {where}. Hand one to each holder, then delete them.")
    else:
        print(__doc__)
