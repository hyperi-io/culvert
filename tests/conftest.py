#  Project:      hyperi-vpn
#  File:         conftest.py
#  Purpose:      Pytest configuration and shared fixtures
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Pytest configuration and shared fixtures."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add scripts directory to path for importing entrypoint
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def clean_env(monkeypatch):
    """Provide a clean environment with no OpenVPN/OAuth2 env vars."""
    env_prefixes = (
        "HYPERI_VPN_",
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


# sample_env fixture removed — all tests now use monkeypatch.setenv
# with HYPERI_VPN_* prefix directly.
# text_log_mode fixture removed — Logger replaced with hyperi_pylib.logger
