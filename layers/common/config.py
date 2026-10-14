"""One place to read config/layers.yaml. Precedence: env var > config file > default."""

import os
from functools import lru_cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _load(path):
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:  # noqa: BLE001 - missing file or yaml: defaults apply
        return {}


def get(section, key, default, env=None):
    if env and os.environ.get(env) not in (None, ""):
        return type(default)(os.environ[env])
    path = os.environ.get("COC_LAYERS_CONFIG", str(REPO / "config" / "layers.yaml"))
    value = (_load(path).get(section) or {}).get(key, default)
    return type(default)(value)
