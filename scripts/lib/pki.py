#  Project:      culvert
#  File:         pki.py
#  Purpose:      PKI initialisation: local Easy-RSA and external PKI support
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
PKI management for culvert.

Supports two modes:
- local: Easy-RSA managed PKI (default)
- external: Fetches certs from FileProvider, OpenBaoProvider, or AWSProvider
  via scalo. Local files are the SSOT; remote providers are the
  update mechanism.
"""

import os
import random
import sys
import time as _time
from datetime import UTC, datetime
from pathlib import Path

from scalo.logger import logger

from lib.process import run

# ---------------------------------------------------------------------------
# PEM validation
# ---------------------------------------------------------------------------


def _validate_pem(data: bytes, name: str) -> bool:
    """Check that data contains a PEM block.

    Anywhere in the file, not only at the start: Easy-RSA and `openssl x509`
    write a human-readable dump of the certificate above the BEGIN line, and
    OpenVPN reads such a file quite happily. Requiring the header first rejected
    the output of the CA culvert itself ships with.

    Non-fragile: logs a warning on failure but never crashes.
    """
    if b"-----BEGIN " in data:
        return True
    logger.error(
        f"Fetched content for '{name}' is not valid PEM (starts with: {data[:40]!r})"
    )
    return False


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def create_manager(cfg):
    """Build a scalo SecretsManager for the configured PKI backend.

    Uses SecretsManager.from_config (the documented construction path)
    rather than hand-built provider classes. The disk cache stays
    DISABLED: it would write a second copy of the server key outside the
    PKI dir. Caller must run the (async) manager.close() coroutine.
    """
    provider_name = cfg.secrets_provider

    if provider_name not in ("file", "openbao", "aws"):
        logger.error(
            f"Unknown secrets provider: '{provider_name}'."
            " Valid options: file, openbao, aws"
        )
        sys.exit(1)

    config: dict = {"cache": {"enabled": False}}
    if provider_name == "openbao":
        config["openbao"] = {
            "address": cfg.secrets_openbao_address,
            "auth": {
                "method": cfg.secrets_openbao_auth_method or "token",
                "token": cfg.secrets_openbao_token or None,
                "role": cfg.secrets_openbao_role or None,
            },
        }
    elif provider_name == "aws":
        config["aws"] = {"region": cfg.secrets_aws_region or "us-east-1"}

    from scalo.secrets import SecretsManager

    return SecretsManager.from_config(config)


# ---------------------------------------------------------------------------
# External PKI fetch
# ---------------------------------------------------------------------------


def _fetch_one(
    manager,
    provider_name: str,
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
        result = manager.get_sync(secret_ref, provider=provider_name)
        data = result.data
        if not _validate_pem(data, name):
            logger.warning(f"Skipping {name} - invalid PEM from '{secret_ref}'")
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(perms)
        logger.info(f"  {name}: written to {dest}")
        return True
    except Exception as e:
        logger.warning(f"Failed to fetch {name} from '{secret_ref}': {e}")
        return False


def _health_check_with_retry(manager, provider_name: str, retries: int = 3) -> bool:
    """Health check the configured provider with jittered backoff."""
    for attempt in range(retries):
        try:
            if manager.health_check_sync().get(provider_name, False):
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

    provider_name = cfg.secrets_provider
    manager = create_manager(cfg)
    try:
        if not _health_check_with_retry(manager, provider_name):
            logger.warning(f"Provider '{provider_name}' is unreachable")
            return False

        # Fetch required certs
        required_ok = all(
            [
                _fetch_one(
                    manager,
                    provider_name,
                    cfg.secrets_ca_cert_path,
                    cfg.pki_dir / "ca.crt",
                    0o644,
                    "CA certificate",
                ),
                _fetch_one(
                    manager,
                    provider_name,
                    cfg.secrets_server_cert_path,
                    cfg.pki_dir / "issued" / "server.crt",
                    0o644,
                    "server certificate",
                ),
                _fetch_one(
                    manager,
                    provider_name,
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
                manager,
                provider_name,
                cfg.secrets_crl_path,
                cfg.pki_dir / "crl.pem",
                0o644,
                "CRL",
            )
        else:
            logger.info("  CRL: not configured (optional)")

        # The tls-crypt-v2 server key. Optional, and minted locally when the
        # provider does not carry one - but then every server has a different
        # key, and a client config only works against the server that issued it.
        # Supply it here to run more than one server behind one address.
        if cfg.secrets_tc_key_path:
            # Required once configured. Asking for a shared key and silently
            # getting a locally minted one is worse than not asking: the install
            # comes up healthy and rejects clients at random, which is the exact
            # failure the setting exists to prevent.
            if not _fetch_one(
                manager,
                provider_name,
                cfg.secrets_tc_key_path,
                cfg.pki_dir / "tc.key",
                0o600,
                "tls-crypt-v2 server key",
            ):
                logger.error(
                    "CULVERT_SECRETS_TC_KEY_PATH is set but the key could not be"
                    f" fetched from '{cfg.secrets_tc_key_path}'. Refusing to mint"
                    " a local one - siblings would reject each other's clients."
                )
                required_ok = False
        else:
            logger.info("  tls-crypt-v2 key: not configured (minted locally)")

        return required_ok
    finally:
        try:
            # close() is async - run the coroutine or aiohttp sessions leak
            import asyncio

            asyncio.run(manager.close())
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
                logger.warning("Provider unavailable - using cached local certs")
            else:
                logger.info("External PKI certs synced successfully")
        else:
            logger.error(
                "No PKI material available -"
                " provider failed and no local certs cached."
                " Ensure the provider is reachable or mount"
                " certs to the PKI directory."
            )
            sys.exit(1)

        # Mint a tls-crypt-v2 key only if the provider did not supply one. A
        # locally minted key is fine for a single server and wrong for several:
        # a client's key derives from it, so siblings reject each other's clients.
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

    # `easyrsa init-pki` is deliberately NOT run. All it creates is the three
    # directories below, and it insists on REMOVING the PKI directory first -
    # unconditionally on 3.2.x, with no opt-out. That is fatal twice over: the
    # directory is a volume mount, so the removal fails outright ("Device or
    # resource busy"), and where it could succeed it would take the CA and
    # every certificate issued from it. This function is reached with a
    # half-built PKI too, since the caller only skips when the CA, the server
    # certificate and the tls-crypt key are ALL present.
    #
    # 3.1.x's spelling for a non-destructive init, `init-pki soft`, is not a
    # portable answer either: 3.2.x reads that argument as a curve name and
    # rejects it, which stops the container starting.
    #
    # Creating the directories ourselves works on both, and build-ca still
    # refuses to overwrite an existing CA - so a half-built PKI fails loudly
    # rather than being silently replaced.
    cfg.pki_dir.mkdir(parents=True, exist_ok=True)
    (cfg.pki_dir / "issued").mkdir(exist_ok=True)
    (cfg.pki_dir / "private").mkdir(exist_ok=True)
    (cfg.pki_dir / "reqs").mkdir(exist_ok=True)

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


# A failed refresh becomes an outage only when nextUpdate passes. Below this
# much remaining life, report it at error.
CRL_EXPIRY_ALARM_SECONDS = 7 * 24 * 3600


def crl_seconds_until_expiry(pki_dir) -> float | None:
    """Seconds until the CRL's nextUpdate, negative once it has passed.

    None when there is no CRL, or openssl cannot read the one there is.
    """
    crl_path = Path(pki_dir) / "crl.pem"
    if not crl_path.exists():
        return None

    result = run(
        f"openssl crl -in {crl_path} -noout -nextupdate",
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        return None

    for line in (result.stdout or "").strip().splitlines():
        if not line.startswith("nextUpdate="):
            continue
        # e.g. "nextUpdate=Aug  4 22:51:20 2026 GMT". openssl pads a
        # single-digit day to two columns; strptime absorbs the run.
        stamp = line.split("=", 1)[1].strip()
        if stamp.endswith(" GMT") or stamp.endswith(" UTC"):
            stamp = stamp[:-4]
        try:
            expiry = datetime.strptime(stamp, "%b %d %H:%M:%S %Y")
        except ValueError:
            logger.warning(f"Could not parse CRL nextUpdate: {stamp}")
            return None
        expiry = expiry.replace(tzinfo=UTC)
        return (expiry - datetime.now(UTC)).total_seconds()

    return None


def log_crl_expiry(cfg) -> float | None:
    """Log how much CRL life is left, at a severity that matches the margin."""
    remaining = crl_seconds_until_expiry(cfg.pki_dir)
    if remaining is None:
        return None

    days = round(remaining / 86400, 1)
    if remaining <= 0:
        logger.error(
            "CRL has expired - OpenVPN is refusing every client, including"
            " valid ones. Regenerate it with `update-crl`.",
            days_since_expiry=abs(days),
        )
    elif remaining <= CRL_EXPIRY_ALARM_SECONDS:
        logger.error(
            "CRL expires soon - every client is refused once it does",
            days_remaining=days,
        )
    else:
        logger.info("CRL is current", days_remaining=days)
    return remaining


def _regenerate_local_crl(cfg) -> bool:
    """Regenerate the CRL from the local CA. True when it was rewritten."""
    # easyrsa is not on PATH; run it from its install dir like every other call
    # site, pointing EASYRSA_PKI at our dir.
    result = run(
        f"cd /usr/share/easy-rsa && EASYRSA_PKI={cfg.pki_dir} ./easyrsa gen-crl",
        check=False,
        capture=True,
    )
    if result.returncode == 0:
        return True
    # Local regeneration reaches nothing off-box, so a failure is a defect
    # rather than a transient.
    logger.error(
        "CRL regeneration failed",
        stderr=(result.stderr[:200] if result.stderr else ""),
    )
    return False


def refetch_external_crl(cfg) -> bool:
    """Re-fetch the CRL from the secrets provider. True when it was rewritten.

    External PKI has no CA key here, so there is nothing to regenerate - the
    authority that revokes is upstream. Re-fetching is what picks a revocation
    up. Without it the CRL is whatever was fetched at startup and a certificate
    revoked upstream keeps working until the container restarts.
    """
    manager = create_manager(cfg)
    try:
        if not _health_check_with_retry(manager, cfg.secrets_provider, retries=2):
            logger.warning(
                f"Provider '{cfg.secrets_provider}' unreachable, keeping the"
                " CRL already on disk"
            )
            return False
        return _fetch_one(
            manager,
            cfg.secrets_provider,
            cfg.secrets_crl_path,
            cfg.pki_dir / "crl.pem",
            0o644,
            "CRL",
        )
    finally:
        try:
            import asyncio

            asyncio.run(manager.close())
        except Exception:
            pass


def crl_refresher(cfg):
    """How to refresh the CRL for this PKI mode, or None when it cannot be.

    Local PKI regenerates from its own CA. External PKI re-fetches from the
    provider, because the CA key is not here. Gating the refresher on local mode
    - as it was - left external deployments serving the startup CRL forever, so
    an upstream revocation took effect only on a restart, silently.

    Returns (callable, description) or None.
    """
    if cfg.pki_mode != "external":
        return _regenerate_local_crl, "regenerated from the local CA"
    if not cfg.secrets_crl_path:
        return None
    return refetch_external_crl, "re-fetched from the secrets provider"


def start_crl_refresh(cfg, proc_manager, interval_hours: int = 24) -> None:
    """Keep the CRL current in the background, by whichever means applies."""
    import threading

    refresher = crl_refresher(cfg)
    if refresher is None:
        logger.warning(
            "External PKI with no CULVERT_SECRETS_CRL_PATH, so revocations made"
            " at the external CA cannot be picked up. Configure it, or restart"
            " the server to load a new CRL."
        )
        return
    refresh, how = refresher

    def refresh_loop():
        interval_seconds = interval_hours * 3600
        while True:
            _time.sleep(interval_seconds)
            if proc_manager.shutdown_requested:
                break
            logger.info("Refreshing CRL...")
            try:
                if refresh(cfg):
                    logger.info("CRL refreshed successfully")
                    # OpenVPN reads the CRL at startup, so a new file changes
                    # nothing until the server re-reads it.
                    proc_manager._reload_handler(None, None)
                else:
                    logger.warning(
                        "CRL was not updated this cycle - the CRL on disk is"
                        " now older than the refresh interval"
                    )
            except Exception as e:
                logger.error(f"CRL refresh error: {e}")
            # Every cycle, whatever happened above. A refresh that keeps
            # failing is only an outage once nextUpdate passes, and the
            # remaining margin is the thing worth escalating on.
            log_crl_expiry(cfg)

    thread = threading.Thread(target=refresh_loop, daemon=True)
    thread.start()
    logger.info(
        f"CRL auto-refresh enabled, {how}",
        interval_hours=interval_hours,
    )
    # The loop sleeps before its first pass, so without this a CRL that is
    # already expired at startup goes unreported for a whole interval.
    log_crl_expiry(cfg)
