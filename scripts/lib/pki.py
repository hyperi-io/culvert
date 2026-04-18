#  Project:      hyperi-vpn
#  File:         pki.py
#  Purpose:      PKI initialisation: local Easy-RSA and external PKI support
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
PKI management for dfe-vpn.

Supports two modes:
- local: Easy-RSA managed PKI (default)
- external: Fetches certs from FileProvider, OpenBaoProvider, or AWSProvider
  via hyperi-pylib. Local files are the SSOT; remote providers are the
  update mechanism.
"""

import os
import random
import sys
import time as _time
from pathlib import Path

from hyperi_pylib.logger import logger

from lib.process import run

# ---------------------------------------------------------------------------
# PEM validation
# ---------------------------------------------------------------------------


def _validate_pem(data: bytes, name: str) -> bool:
    """Check that data starts with a PEM header.

    Non-fragile: logs a warning on failure but never crashes.
    """
    if data.strip().startswith(b"-----BEGIN "):
        return True
    logger.error(
        f"Fetched content for '{name}' is not valid PEM (starts with: {data[:40]!r})"
    )
    return False


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def create_provider(cfg):
    """Create a hyperi-pylib SecretProvider from config.

    Returns the provider instance. Caller must call provider.close().
    """
    provider_name = cfg.secrets_provider

    if provider_name == "file":
        from hyperi_pylib.secrets.providers.file import (
            FileProvider,
        )

        return FileProvider()

    if provider_name == "openbao":
        from hyperi_pylib.secrets.providers.openbao import (
            OpenBaoProvider,
        )
        from hyperi_pylib.secrets.types import OpenBaoConfig

        bao_cfg = OpenBaoConfig(
            address=cfg.secrets_openbao_address,
            auth_method=(cfg.secrets_openbao_auth_method or "token"),
            token=cfg.secrets_openbao_token or None,
            role=cfg.secrets_openbao_role or None,
        )
        return OpenBaoProvider(config=bao_cfg)

    if provider_name == "aws":
        from hyperi_pylib.secrets.providers.aws import (
            AWSProvider,
        )
        from hyperi_pylib.secrets.types import AWSConfig

        aws_cfg = AWSConfig(
            region=cfg.secrets_aws_region or "us-east-1",
        )
        return AWSProvider(config=aws_cfg)

    logger.error(
        f"Unknown secrets provider: '{provider_name}'."
        " Valid options: file, openbao, aws"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# External PKI fetch
# ---------------------------------------------------------------------------


def _fetch_one(
    provider,
    secret_ref: str,
    dest: Path,
    perms: int,
    name: str,
) -> bool:
    """Fetch a single secret and write to disk if valid PEM.

    Returns True if the file was successfully written.
    Does not overwrite existing local file if fetched content is invalid.
    """
    try:
        result = provider.get_sync(secret_ref)
        data = result.data
        if not _validate_pem(data, name):
            logger.warning(f"Skipping {name} — invalid PEM from '{secret_ref}'")
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(perms)
        logger.info(f"  {name}: written to {dest}")
        return True
    except Exception as e:
        logger.warning(f"Failed to fetch {name} from '{secret_ref}': {e}")
        return False


def _health_check_with_retry(provider, retries: int = 3) -> bool:
    """Health check with jittered backoff."""
    for attempt in range(retries):
        try:
            if provider.health_check_sync():
                return True
        except Exception as e:
            logger.warning(
                f"Provider health check attempt {attempt + 1}/{retries}: {e}"
            )
        if attempt < retries - 1:
            delay = 5 + random.uniform(0, 2)
            _time.sleep(delay)
    return False


def fetch_external_pki(cfg) -> bool:
    """Fetch PKI material from external provider.

    Returns True if all required certs were successfully fetched.
    Returns False if the provider is unreachable or secrets are missing
    (caller should fall back to local files).
    """
    logger.info(f"Fetching PKI from external provider: {cfg.secrets_provider}")

    provider = create_provider(cfg)
    try:
        if not _health_check_with_retry(provider):
            logger.warning(f"Provider '{cfg.secrets_provider}' is unreachable")
            return False

        # Fetch required certs
        required_ok = all(
            [
                _fetch_one(
                    provider,
                    cfg.secrets_ca_cert_path,
                    cfg.pki_dir / "ca.crt",
                    0o644,
                    "CA certificate",
                ),
                _fetch_one(
                    provider,
                    cfg.secrets_server_cert_path,
                    cfg.pki_dir / "issued" / "server.crt",
                    0o644,
                    "server certificate",
                ),
                _fetch_one(
                    provider,
                    cfg.secrets_server_key_path,
                    cfg.pki_dir / "private" / "server.key",
                    0o600,
                    "server private key",
                ),
            ]
        )

        # CRL is optional
        if cfg.secrets_crl_path:
            _fetch_one(
                provider,
                cfg.secrets_crl_path,
                cfg.pki_dir / "crl.pem",
                0o644,
                "CRL",
            )
        else:
            logger.info("  CRL: not configured (optional)")

        return required_ok
    finally:
        try:
            result = provider.close()
            # Handle async close() returning a coroutine
            if result is not None:
                import asyncio

                try:
                    asyncio.get_event_loop().run_until_complete(result)
                except RuntimeError:
                    pass
        except Exception:
            pass


# ---------------------------------------------------------------------------
# PKI initialisation
# ---------------------------------------------------------------------------


def validate_external_pki_files(pki_dir: Path) -> None:
    """Validate that external PKI files exist at convention paths.

    Expected layout:
        pki_dir/ca.crt
        pki_dir/issued/server.crt
        pki_dir/private/server.key
        pki_dir/crl.pem
    """
    required = [
        pki_dir / "ca.crt",
        pki_dir / "issued" / "server.crt",
        pki_dir / "private" / "server.key",
        pki_dir / "crl.pem",
    ]

    missing = [str(p) for p in required if not p.exists()]

    if missing:
        for path in missing:
            logger.error(f"External PKI file missing: {path}")
        logger.error(
            "External PKI mode requires all certificate files"
            " to be mounted at convention paths"
        )
        sys.exit(1)

    logger.info("External PKI files validated")


def init_pki(cfg) -> None:
    """Initialize PKI based on mode.

    Local mode: Easy-RSA generates certs if not present.
    External mode: Tries to fetch from provider, falls back to
    local files if provider is unreachable.
    """
    logger.info(f"Initializing PKI (mode: {cfg.pki_mode})...")

    if cfg.pki_mode == "external":
        # Ensure directory structure exists
        cfg.pki_dir.mkdir(parents=True, exist_ok=True)
        (cfg.pki_dir / "issued").mkdir(exist_ok=True)
        (cfg.pki_dir / "private").mkdir(exist_ok=True)

        # Try to fetch from remote provider
        fetched = fetch_external_pki(cfg)

        # Check if local files exist (freshly fetched or cached)
        ca_crt = cfg.pki_dir / "ca.crt"
        server_crt = cfg.pki_dir / "issued" / "server.crt"
        server_key = cfg.pki_dir / "private" / "server.key"

        if ca_crt.exists() and server_crt.exists() and server_key.exists():
            if not fetched:
                logger.warning("Provider unavailable — using cached local certs")
            else:
                logger.info("External PKI certs synced successfully")
        else:
            logger.error(
                "No PKI material available —"
                " provider failed and no local certs cached."
                " Ensure the provider is reachable or mount"
                " certs to the PKI directory."
            )
            sys.exit(1)

        # tls-crypt-v2 key is always local
        tc_key = cfg.pki_dir / "tc.key"
        if not tc_key.exists():
            generate_tc_key(cfg.pki_dir)
        return

    # Local mode: check if already initialized
    ca_crt = cfg.pki_dir / "ca.crt"
    server_crt = cfg.pki_dir / "issued" / "server.crt"
    tc_key = cfg.pki_dir / "tc.key"

    if ca_crt.exists() and server_crt.exists() and tc_key.exists():
        logger.info("Local PKI already initialized, skipping...")
        return

    # Local PKI with Easy-RSA
    init_pki_local(cfg)


def generate_tc_key(pki_dir: Path) -> None:
    """Generate tls-crypt-v2 server key."""
    tc_key = pki_dir / "tc.key"
    run(f"openvpn --genkey tls-crypt-v2-server {tc_key}")
    tc_key.chmod(0o600)
    logger.info("tls-crypt-v2 key generated")


def init_pki_local(cfg) -> None:
    """Initialize local PKI with Easy-RSA."""
    logger.info("Initializing local Easy-RSA PKI...")

    easyrsa = Path("/usr/share/easy-rsa")
    if not easyrsa.exists():
        logger.error("Easy-RSA not found at /usr/share/easy-rsa")
        sys.exit(1)

    # Set Easy-RSA environment
    env_vars = {
        "EASYRSA": str(easyrsa),
        "EASYRSA_PKI": str(cfg.pki_dir),
        "EASYRSA_REQ_CN": cfg.ca_cn,
        "EASYRSA_BATCH": "1",
        "EASYRSA_CA_EXPIRE": "3650",
        "EASYRSA_CERT_EXPIRE": "730",
        "EASYRSA_CRL_DAYS": "180",
    }

    if cfg.key_type == "ec":
        env_vars["EASYRSA_ALGO"] = "ec"
        env_vars["EASYRSA_CURVE"] = cfg.key_size
    else:
        env_vars["EASYRSA_ALGO"] = "rsa"
        env_vars["EASYRSA_KEY_SIZE"] = cfg.key_size

    os.environ.update(env_vars)

    # Create PKI directories
    cfg.pki_dir.mkdir(parents=True, exist_ok=True)
    (cfg.pki_dir / "issued").mkdir(exist_ok=True)
    (cfg.pki_dir / "private").mkdir(exist_ok=True)
    (cfg.pki_dir / "reqs").mkdir(exist_ok=True)

    # Initialize PKI
    run(f"cd {easyrsa} && ./easyrsa init-pki soft")
    run(f"cd {easyrsa} && ./easyrsa build-ca nopass")

    # Generate server cert
    os.environ["EASYRSA_REQ_CN"] = cfg.server_cn
    run(f"cd {easyrsa} && ./easyrsa gen-req server nopass")
    run(f"cd {easyrsa} && ./easyrsa sign-req server server")

    # Generate tls-crypt-v2 key
    generate_tc_key(cfg.pki_dir)

    # Generate CRL
    run(f"cd {easyrsa} && ./easyrsa gen-crl")

    # Set permissions
    for key in (cfg.pki_dir / "private").glob("*.key"):
        key.chmod(0o600)
    (cfg.pki_dir / "ca.crt").chmod(0o644)
    (cfg.pki_dir / "crl.pem").chmod(0o644)

    logger.info("Local PKI initialized successfully")
    logger.info(f"  CA: {cfg.ca_cn}")
    logger.info(f"  Server: {cfg.server_cn}")
    logger.info(f"  Algorithm: {cfg.key_type} ({cfg.key_size})")


def start_crl_refresh(cfg, proc_manager, interval_hours: int = 24) -> None:
    """Start CRL auto-refresh in background thread."""
    import threading

    def refresh_loop():
        interval_seconds = interval_hours * 3600
        while True:
            _time.sleep(interval_seconds)
            if proc_manager.shutdown_requested:
                break
            logger.info("Auto-refreshing CRL...")
            try:
                result = run(
                    f"cd {cfg.pki_dir} && EASYRSA_PKI={cfg.pki_dir} easyrsa gen-crl",
                    check=False,
                    capture=True,
                )
                if result.returncode == 0:
                    logger.info("CRL refreshed successfully")
                    proc_manager._reload_handler(None, None)
                else:
                    logger.warning(
                        "CRL refresh failed",
                        stderr=(result.stderr[:200] if result.stderr else ""),
                    )
            except Exception as e:
                logger.warning(f"CRL refresh error: {e}")

    thread = threading.Thread(target=refresh_loop, daemon=True)
    thread.start()
    logger.info(
        "CRL auto-refresh enabled",
        interval_hours=interval_hours,
    )
