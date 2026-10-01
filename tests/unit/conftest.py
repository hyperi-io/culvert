#  Project:      culvert
#  File:         conftest.py
#  Purpose:      Unit-tier fixtures shared across test modules
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit-tier fixtures shared across test modules."""

import signal
import sys

import pytest
from lib.process import ProcessManager

# Records how lib.pki invoked it, so a test can assert the arguments and the
# environment Easy-RSA would have seen.
FAKE_EASYRSA = """
import json
import os
import sys
from pathlib import Path

command = sys.argv[1]
if os.environ.get("FAKE_EASYRSA_FAIL") == command:
    sys.exit(f"Easy-RSA error: {command} failed")
if command != "gen-crl":
    sys.exit(0)
# Easy-RSA runs under umask 077, so a crl.pem it creates is 0600.
os.umask(0o077)
record = {
    "argv": sys.argv[1:],
    "cwd": os.getcwd(),
    "easyrsa": os.environ.get("EASYRSA"),
    "pki": os.environ.get("EASYRSA_PKI"),
    "batch": os.environ.get("EASYRSA_BATCH"),
    "crl_days": os.environ.get("EASYRSA_CRL_DAYS"),
}
Path(os.environ["EASYRSA_PKI"], "crl.pem").write_text(json.dumps(record))
"""


@pytest.fixture
def manager():
    """A ProcessManager whose children and signal handlers are cleaned up after."""
    handled = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    saved = {sig: signal.getsignal(sig) for sig in handled}
    pm = ProcessManager()
    yield pm
    for proc in pm.processes.values():
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    for log_f in pm._daemon_logs.values():
        log_f.close()
    for sig, handler in saved.items():
        signal.signal(sig, handler)


@pytest.fixture
def easyrsa(tmp_path, monkeypatch):
    """A stand-in Easy-RSA install that lib.pki runs in place of the real one.

    Easy-RSA is not on a CI runner; the container tier covers the real one.
    """
    import lib.pki

    install = tmp_path / "easy-rsa"
    install.mkdir()
    script = install / "easyrsa"
    script.write_text(f"#!{sys.executable}\n{FAKE_EASYRSA}", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setattr(lib.pki, "EASYRSA_DIR", install)
    # An inherited EASYRSA_CRL_DAYS must not stand in for the one lib.pki passes.
    monkeypatch.delenv("EASYRSA_CRL_DAYS", raising=False)
    return install
