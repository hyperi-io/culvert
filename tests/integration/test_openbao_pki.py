#  Project:      hyperi-vpn
#  File:         test_openbao_pki.py
#  Purpose:      Integration test: fetch PKI certs from real OpenBao
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Integration test: fetch PKI certs from real OpenBao.

Requires OPENBAO_ADDR and OPENBAO_TOKEN environment variables.
Skipped if not set (CI without infra access).

To run manually:
    source /projects/hyperi-infra/.env
    pytest tests/integration/test_openbao_pki.py -v
"""

import json
import os
import ssl
import urllib.request

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("OPENBAO_ADDR"),
    reason="OPENBAO_ADDR not set — no OpenBao access",
)

FAKE_CA = (
    "-----BEGIN CERTIFICATE-----\n"
    "TEST_CA_CERT_FOR_HYPERI_VPN_INTEGRATION\n"
    "-----END CERTIFICATE-----\n"
)
FAKE_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "TEST_SERVER_CERT_FOR_HYPERI_VPN_INTEGRATION\n"
    "-----END CERTIFICATE-----\n"
)
FAKE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "TEST_SERVER_KEY_FOR_HYPERI_VPN_INTEGRATION\n"
    "-----END PRIVATE KEY-----\n"
)

SECRET_BASE = "secret/data/dfe-vpn-test"
TEST_SECRETS = {
    "ca-cert": FAKE_CA,
    "server-cert": FAKE_CERT,
    "server-key": FAKE_KEY,
}


def _bao_request(method: str, path: str, data: dict | None = None):
    """Make an HTTP request to OpenBao."""
    addr = os.environ["OPENBAO_ADDR"].rstrip("/")
    token = os.environ.get("OPENBAO_TOKEN", "")
    headers = {
        "X-Vault-Token": token,
        "Content-Type": "application/json",
    }

    url = f"{addr}/v1/{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    ctx = ssl.create_default_context()
    skip = os.environ.get("OPENBAO_SKIP_VERIFY", "").lower()
    if skip in ("1", "true"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return urllib.request.urlopen(req, timeout=10, context=ctx)


@pytest.fixture(scope="module")
def openbao_test_secrets():
    """Store test secrets in OpenBao, yield, then clean up."""
    # Write test secrets
    for name, content in TEST_SECRETS.items():
        _bao_request(
            "POST",
            f"{SECRET_BASE}/{name}",
            {"data": {"value": content}},
        )

    yield

    # Cleanup
    for name in TEST_SECRETS:
        try:
            _bao_request("DELETE", f"{SECRET_BASE}/{name}")
        except Exception:
            pass


def test_openbao_health():
    """OpenBao is reachable and healthy."""
    from hyperi_pylib.secrets.providers.openbao import (
        OpenBaoProvider,
    )
    from hyperi_pylib.secrets.types import OpenBaoConfig

    cfg = OpenBaoConfig(
        address=os.environ["OPENBAO_ADDR"],
        token=os.environ.get("OPENBAO_TOKEN"),
        skip_verify=os.environ.get("OPENBAO_SKIP_VERIFY", "").lower() in ("1", "true"),
    )
    provider = OpenBaoProvider(config=cfg)
    assert provider.health_check_sync() is True
    provider.close()


def test_fetch_certs_from_openbao(openbao_test_secrets, tmp_path):
    """Fetch test certs from real OpenBao via full external PKI flow."""
    from lib.config import Config
    from lib.pki import fetch_external_pki

    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "issued").mkdir()
    (pki / "private").mkdir()

    cfg = Config(
        pki_mode="external",
        pki_dir=pki,
        secrets_provider="openbao",
        secrets_openbao_address=os.environ["OPENBAO_ADDR"],
        secrets_openbao_auth_method="token",
        secrets_openbao_token=os.environ.get("OPENBAO_TOKEN", ""),
        secrets_ca_cert_path=f"{SECRET_BASE}/ca-cert",
        secrets_server_cert_path=f"{SECRET_BASE}/server-cert",
        secrets_server_key_path=f"{SECRET_BASE}/server-key",
    )

    result = fetch_external_pki(cfg)
    assert result is True

    ca = (pki / "ca.crt").read_text()
    assert "TEST_CA_CERT" in ca

    cert = (pki / "issued" / "server.crt").read_text()
    assert "TEST_SERVER_CERT" in cert

    key = (pki / "private" / "server.key").read_text()
    assert "TEST_SERVER_KEY" in key
