"""Download the Linux wheels the images need, so `docker compose build` works without internet.

    python docker/fetch_wheels.py
"""
import subprocess
import sys
from pathlib import Path

PACKAGES = ["fastapi==0.115.12", "uvicorn==0.34.0", "PyYAML==6.0.3", "cryptography==50.0.2", "requests==2.33.1",
            "psycopg[binary]==3.2.13", "pycryptodome==3.23.0"]
OUT = Path(__file__).resolve().parent / "wheels"
subprocess.run([sys.executable, "-m", "pip", "download", "--dest", str(OUT), "--only-binary=:all:",
                "--platform", "manylinux2014_x86_64", "--platform", "manylinux_2_17_x86_64",
                "--platform", "manylinux_2_28_x86_64", "--platform", "manylinux_2_34_x86_64",
                "--python-version", "3.12", "--implementation", "cp", *PACKAGES], check=True)
print(f"{len(list(OUT.glob('*.whl')))} wheels in {OUT}")
