#  Project:      culvert
#  File:         conftest.py
#  Purpose:      Pytest configuration and shared fixtures
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Pytest configuration and shared fixtures."""

import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

# Add scripts directory to path for importing entrypoint
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# This directory holds tidy.py, which the docker and k8s conftests also import.
sys.path.insert(0, str(Path(__file__).parent))

from tidy import install_signal_handler, run_teardowns  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    """Arm the orderly-shutdown path for the tiers that build real infra."""
    install_signal_handler()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Run cleanups registered by any tier, however the session ended."""
    run_teardowns()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def clean_env(monkeypatch):
    """Provide a clean environment with no OpenVPN/OAuth2 env vars."""
    env_prefixes = (
        "CULVERT_",
        "OAUTH2_",  # keep for openvpn-auth-oauth2's own env inputs
    )
    for key in list(os.environ.keys()):
        if key.startswith(env_prefixes):
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def mock_pki_dir(temp_dir):
    """Create a mock PKI directory structure."""
    pki_dir = temp_dir / "pki"
    pki_dir.mkdir()
    (pki_dir / "issued").mkdir()
    (pki_dir / "private").mkdir()
    (pki_dir / "reqs").mkdir()
    return pki_dir


@pytest.fixture
def write_crl():
    """Write a real, openssl-parseable CRL expiring at a given time.

    Real X.509 rather than a stubbed string: the code under test shells out
    to `openssl crl`, so anything less would not exercise the parse.
    """

    def _write(path, next_update):
        from datetime import timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "culvert-test-ca")])
        # Issued before it expires, whether next_update is past or future.
        last_update = min(datetime.now(UTC), next_update) - timedelta(days=1)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer)
            .last_update(last_update)
            .next_update(next_update)
            .sign(private_key=key, algorithm=hashes.SHA256())
        )
        path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    return _write
