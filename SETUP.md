# Setup

## Prerequisites

- Python 3.11+ (the README asks for 3.11; the test suite was run on 3.14)
- pip
- Layer 1 (command tripwire) runs in WSL Ubuntu or any Linux

## Install

```bash
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Run the witness service

`witness/app.py` has no `__main__` block, so `python witness/app.py` does nothing. Start it with uvicorn from the repo root:

```bash
python -m uvicorn --factory witness.app:create_app --port 8000
```

The auditor view is at **http://127.0.0.1:8000/**. The port is 8000; the agent reads it from `WITNESS_URL` (default `http://127.0.0.1:8000`).

To run the whole demo (fresh witness, fake bank and agent, menu):

```bash
python demo/demo.py
```

## Run the tests

```bash
pytest tests/ -v
```

Fast subset (no Docker, no T0):

```bash
python -m pytest -q -m "not slow and not docker"
```

The full run is slow. T0 (`-m slow`) and the container tests (`-m docker`, which needs the stack up) are excluded from the fast subset.

## What the named tests demonstrate

- **T9b** (`tests/test_classify.py`): editing `amount_paise` on a stored entry makes `/alerts` name the field and show the old and new values.
- **T6a** (`tests/test_layer1.py`): an attacker calling `/usr/bin/nano` directly bypasses the wrapper, and the auditd backstop still catches it and raises a Layer 1 alert.
- **T5c** (`tests/test_layer1.py`): renaming a temp file over the real log with `mv` is caught by the wrapper; in deception mode the real file is never touched.
- **T7a** (`tests/test_layer3.py`): when the agent goes silent, a silence alert fires at 15 s and quarantine is presumed at 45 s.
