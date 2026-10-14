import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_PREV_HASH = base64.b64encode(b"\x00" * 32).decode("utf-8")

def _check_no_floats(obj):
    if isinstance(obj, float):
        raise TypeError("Floats are not permitted in canonical encoding; use integer paise")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_no_floats(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_no_floats(item)

def canonical_encode(data: dict | list) -> bytes:
    _check_no_floats(data)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_digest(data: bytes | dict | list) -> str:
    if isinstance(data, (dict, list)):
        raw = canonical_encode(data)
    elif isinstance(data, bytes):
        raw = data
    else:
        raise TypeError(f"Unsupported data type for digest: {type(data)}")
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("utf-8")

def hash_entry(entry: dict) -> str:
    fields = {k: v for k, v in entry.items() if k not in ("hash", "signature")}
    return sha256_digest(fields)

def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode("utf-8")
    return priv, pub_b64

def export_public_key(priv: ed25519.Ed25519PrivateKey) -> str:
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode("utf-8")

def sign_payload(private_key: ed25519.Ed25519PrivateKey, payload: dict | bytes) -> str:
    data = canonical_encode(payload) if isinstance(payload, dict) else payload
    sig = private_key.sign(data)
    return base64.b64encode(sig).decode("utf-8")

def verify_signature(public_key_b64: str, payload: dict | bytes, signature_b64: str) -> bool:
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64)
        data = canonical_encode(payload) if isinstance(payload, dict) else payload
        pub_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64decode(s: str) -> bytes:
    return base64.b64decode(s)
