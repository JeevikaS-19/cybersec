"""Profile-ids: the team's secret per platform. Stored only as scrypt hashes, never in plain text.

    python -m layers.l1_tripwire.profiles add <platform>     # asks for the profile-id, stores its hash
    python -m layers.l1_tripwire.profiles list               # platform names only
    python -m layers.l1_tripwire.profiles remove <platform>
"""

import base64
import getpass
import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path


def profiles_file():
    from layers.l1_tripwire.trip import settings
    return Path(os.environ.get("COC_PROFILES") or settings()["profiles_file"])


def _scrypt(value, salt):
    return hashlib.scrypt(value.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def _load():
    path = profiles_file()
    try:
        if not path.exists():
            return []
        text = path.read_text()
    except PermissionError:
        return []  # can't read the hashes: no profile matches, the command trips
    rows = []
    for line in text.splitlines():
        try:
            name, _, salt, digest = line.strip().split("$")
            rows.append((name, base64.b64decode(salt), base64.b64decode(digest)))
        except ValueError:
            continue
    return rows


def _save(rows):
    path = profiles_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{n}$scrypt${base64.b64encode(s).decode()}${base64.b64encode(d).decode()}\n"
                            for n, s, d in rows))
    os.chmod(path, 0o600)


def add(name, profile_id):
    if not name or "$" in name or len(profile_id) < 8:
        raise ValueError("platform name must not contain '$' and the profile-id needs 8+ characters")
    salt = secrets.token_bytes(16)
    _save([r for r in _load() if r[0] != name] + [(name, salt, _scrypt(profile_id, salt))])


def remove(name):
    _save([r for r in _load() if r[0] != name])


def match(candidate):
    """Platform name whose profile-id equals candidate, else None. Constant-time per stored hash."""
    found = None
    for name, salt, digest in _load():
        if hmac.compare_digest(_scrypt(candidate, salt), digest):
            found = name
    return found


def main():
    args = sys.argv[1:]
    if args[:1] == ["list"]:
        for name, _, _ in _load():
            print(name)
        return 0
    if args[:1] == ["remove"] and len(args) == 2:
        remove(args[1])
        return 0
    if args[:1] == ["add"] and len(args) == 2:
        profile_id = os.environ.pop("COC_PROFILE_ID", None) or getpass.getpass(f"profile-id for {args[1]}: ")
        add(args[1], profile_id)
        print(f"profile {args[1]} stored (hash only) in {profiles_file()}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
