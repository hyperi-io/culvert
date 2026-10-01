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


@pytest.fixture
def issue_cert():
    """Issue a real X.509 certificate, self-signed or signed by a given issuer.

    Real certificates rather than stubbed strings: the code under test shells out
    to `openssl x509`, so anything less would not exercise the parse. Returns a
    namespace carrying the certificate and key objects plus their PEM encodings.
    """
    from datetime import timedelta
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def _issue(common_name, *, sans=(), issuer=None, valid_days=30, is_ca=False):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(UTC)
        # A negative lifetime issues a certificate that has already expired.
        not_after = now + timedelta(days=valid_days)
        not_before = min(now, not_after) - timedelta(days=1)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.cert.subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
            )
        )
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in sans]),
                critical=False,
            )
        cert = builder.sign(issuer.key if issuer else key, hashes.SHA256())
        return SimpleNamespace(
            cert=cert,
            key=key,
            cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            key_pem=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    return _issue
