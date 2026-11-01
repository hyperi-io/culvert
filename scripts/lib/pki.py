#  Project:      culvert
#  File:         pki.py
#  Purpose:      PKI initialisation: local Easy-RSA and external PKI support
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""PKI management for culvert.

Supports two modes:
- local: Easy-RSA managed PKI (default)
- external: Fetches certs from FileProvider, OpenBaoProvider, or AWSProvider
  via scalo. Local files are the SSOT; remote providers are the
  update mechanism.
"""

import os
import random
import re
import shlex
import subprocess
import sys
import tempfile
import time as _time
from datetime import UTC, datetime
from pathlib import Path

from scalo.logger import logger

from lib.process import run, write_file_atomic

# Easy-RSA is not on PATH, so it is run from its install directory.
EASYRSA_DIR = Path("/usr/share/easy-rsa")

# ---------------------------------------------------------------------------
# Client name validation
# ---------------------------------------------------------------------------


def validate_client_name(name: str) -> bool:
    """Validate a client name contains only safe characters.

    Shared by generate-client.py and revoke-client.py: both interpolate the
    name into PKI file paths (PKI_DIR / "issued" / f"{name}.crt"), so a name
    carrying "../" or a path separator must be refused before it reaches one.
    """
    if not name:
        return False
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", name))


def client_tc_key_path(pki_dir: Path, client_name: str) -> Path:
    """Return where a client's tls-crypt-v2 key lives.

    Outside Easy-RSA's private/ directory, so it can never be another client's
    private key: "<alice>-tc.key" there was also the key of a client "alice-tc".
    """
    return Path(pki_dir) / "tls-crypt-v2" / f"{client_name}.key"


# ---------------------------------------------------------------------------
# PKI material validation
# ---------------------------------------------------------------------------

TC_SERVER_KEY_BEGIN = b"-----BEGIN OpenVPN tls-crypt-v2 server key-----"
TC_SERVER_KEY_END = b"-----END OpenVPN tls-crypt-v2 server key-----"


def _openssl(args: list[str], data: bytes) -> subprocess.CompletedProcess:
    """Run openssl on data from stdin, so key material never touches a file."""
    return subprocess.run(
        ["openssl", *args], input=data, capture_output=True, check=False
    )


def crl_problem(crl: bytes, ca_file: Path) -> str | None:
    """Return why crl cannot be used with the CA in ca_file, or None."""
    if _openssl(["crl", "-noout", "-CAfile", str(ca_file)], crl).returncode != 0:
        return "the CRL is not a CRL signed by the CA"
    return None


def pki_set_problems(
    ca: bytes,
    cert: bytes,
    key: bytes,
    crl: bytes | None = None,
    tc_key: bytes | None = None,
) -> list[str]:
    """Return what stops this material serving as one server's PKI, empty if none.

    Each file parsing is not enough: a key from another server, or a certificate
    from another CA, passes that and fails every client handshake. The server
    certificate is also checked for expiry, by the chain verification.
    """
    problems = []
    if _openssl(["x509", "-noout"], ca).returncode != 0:
        return ["the CA certificate is not an X.509 certificate"]

    cert_public = _openssl(["x509", "-noout", "-pubkey"], cert)
    key_public = _openssl(["pkey", "-pubout"], key)
    if cert_public.returncode != 0:
        problems.append("the server certificate is not an X.509 certificate")
    if key_public.returncode != 0:
        problems.append("the server private key is not a private key")
    elif cert_public.returncode == 0 and cert_public.stdout != key_public.stdout:
        problems.append("the server private key does not match the server certificate")

    with tempfile.TemporaryDirectory() as tmp:
        ca_file = Path(tmp) / "ca.crt"
        ca_file.write_bytes(ca)
        if cert_public.returncode == 0:
            verify = _openssl(["verify", "-CAfile", str(ca_file)], cert)
            if verify.returncode != 0:
                detail = verify.stderr.decode("utf-8", "replace").strip()
                problems.append(f"the server certificate does not verify: {detail}")
        if crl is not None and (problem := crl_problem(crl, ca_file)):
            problems.append(problem)

    if tc_key is not None and not (
        TC_SERVER_KEY_BEGIN in tc_key and TC_SERVER_KEY_END in tc_key
    ):
        problems.append(
            "the tls-crypt-v2 key is not an OpenVPN tls-crypt-v2 server key"
        )
    return problems


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
        # An unset region is never pinned: scalo reads AWS_REGION, then the SDK profile.
        config["aws"] = {"region": cfg.secrets_aws_region}

    from scalo.secrets import SecretsManager

    return SecretsManager.from_config(config)


# ---------------------------------------------------------------------------
# External PKI fetch
# ---------------------------------------------------------------------------


def _fetch_one(manager, provider_name: str, secret_ref: str, name: str) -> bytes | None:
    """Fetch one secret's bytes, or None when the provider cannot supply it."""
    try:
        return manager.get_sync(secret_ref, provider=provider_name).data
    except Exception as e:
        logger.warning(f"Failed to fetch {name} from '{secret_ref}': {e}")
        return None


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
            delay = 5 + random.uniform(0, 2)  # noqa: S311 - retry jitter, not a secret
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

        wanted = {
            "CA certificate": (cfg.secrets_ca_cert_path, "ca.crt", 0o644),
            "server certificate": (
                cfg.secrets_server_cert_path,
                "issued/server.crt",
                0o644,
            ),
            "server private key": (
                cfg.secrets_server_key_path,
                "private/server.key",
                0o600,
            ),
        }
        if cfg.secrets_crl_path:
            wanted["CRL"] = (cfg.secrets_crl_path, "crl.pem", 0o644)
        else:
            logger.info("  CRL: not configured (optional)")
        # The tls-crypt-v2 server key. Optional, and minted locally when the
        # provider does not carry one - but then every server has a different
        # key, and a client config only works against the server that issued it.
        # Supply it here to run more than one server behind one address.
        if cfg.secrets_tc_key_path:
            wanted["tls-crypt-v2 server key"] = (
                cfg.secrets_tc_key_path,
                "tc.key",
                0o600,
            )
        else:
            logger.info("  tls-crypt-v2 key: not configured (minted locally)")

        fetched = {
            name: _fetch_one(manager, provider_name, ref, name)
            for name, (ref, _, _) in wanted.items()
        }
        # Required once configured, the shared tls-crypt-v2 key included. Asking
        # for a shared key and silently getting a locally minted one is worse
        # than not asking: the install comes up healthy and rejects clients at
        # random, which is the exact failure the setting exists to prevent.
        missing = [
            name for name, data in fetched.items() if data is None and name != "CRL"
        ]
        if missing:
            logger.error(
                f"Not writing any fetched PKI material: missing {', '.join(missing)}"
            )
            return False
        if "CRL" in fetched and fetched["CRL"] is None:
            logger.warning("CRL could not be fetched, keeping the one on disk")
        material = {name: data for name, data in fetched.items() if data is not None}

        problems = pki_set_problems(
            material["CA certificate"],
            material["server certificate"],
            material["server private key"],
            crl=material.get("CRL"),
            tc_key=material.get("tls-crypt-v2 server key"),
        )
        if problems:
            for problem in problems:
                logger.error(f"Fetched PKI rejected: {problem}")
            logger.error(
                "Not writing any fetched PKI material, keeping what is on disk"
            )
            return False

        # Only a set that passed together is written, so the files on disk are
        # never one server's certificate beside another's key.
        for name, data in material.items():
            _, relative, perms = wanted[name]
            dest = cfg.pki_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            write_file_atomic(dest, data, perms)
            logger.info(f"  {name}: written to {dest}")
        return True
    finally:
        try:
            # close() is async - run the coroutine or aiohttp sessions leak
            import asyncio

            asyncio.run(manager.close())
        except Exception as e:
            logger.debug(f"Secrets provider close failed: {e}")


# ---------------------------------------------------------------------------
# PKI initialisation
# ---------------------------------------------------------------------------


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

        # Mint a tls-crypt-v2 key only when none is configured. A locally minted
        # key is fine for a single server and wrong for several: a client's key
        # derives from it, so siblings reject each other's clients.
        tc_key = cfg.pki_dir / "tc.key"
        if not tc_key.exists():
            if cfg.secrets_tc_key_path:
                logger.error(
                    "CULVERT_SECRETS_TC_KEY_PATH is set, but the shared"
                    f" tls-crypt-v2 key could not be fetched from"
                    f" '{cfg.secrets_tc_key_path}' and none is cached. Refusing to"
                    " mint a local one - siblings would reject each other's clients."
                )
                sys.exit(1)
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

    easyrsa = EASYRSA_DIR
    if not easyrsa.exists():
        logger.error(f"Easy-RSA not found at {easyrsa}")
        sys.exit(1)

    # Set Easy-RSA environment
    env_vars = {
        "EASYRSA": str(easyrsa),
        "EASYRSA_PKI": str(cfg.pki_dir),
        "EASYRSA_REQ_CN": cfg.ca_cn,
        "EASYRSA_BATCH": "1",
        "EASYRSA_CA_EXPIRE": str(cfg.ca_expire_days),
        "EASYRSA_CERT_EXPIRE": str(cfg.cert_expire_days),
        "EASYRSA_CRL_DAYS": str(cfg.crl_days),
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


def revoked_serials(pki_dir) -> frozenset[str]:
    """Return the serial numbers the CRL revokes, empty with no readable CRL."""
    crl_path = Path(pki_dir) / "crl.pem"
    if not crl_path.exists():
        return frozenset()
    result = run(
        ["openssl", "crl", "-in", str(crl_path), "-noout", "-text"],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        return frozenset()
    return frozenset(re.findall(r"Serial Number: ([0-9A-Fa-f]+)", result.stdout))


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


def regenerate_local_crl(cfg) -> bool:
    """Regenerate the CRL from the local CA. True when it was rewritten.

    Shared by the server's refresh loop, update-crl and revoke-client. Reads
    cfg.pki_dir and cfg.crl_days.
    """
    easyrsa = shlex.quote(str(EASYRSA_DIR))
    pki_dir = shlex.quote(str(cfg.pki_dir))
    # Passed on every run: a process that did not initialise the PKI has no
    # EASYRSA_CRL_DAYS, and Easy-RSA then falls back to its own 180 days.
    crl_days = shlex.quote(str(cfg.crl_days))
    result = run(
        f"cd {easyrsa} && EASYRSA={easyrsa} EASYRSA_PKI={pki_dir} EASYRSA_BATCH=1"
        f" EASYRSA_CRL_DAYS={crl_days} ./easyrsa gen-crl",
        check=False,
        capture=True,
    )
    if result.returncode == 0:
        # gen-crl creates a missing crl.pem as 0600, which OpenVPN cannot read
        # once it has dropped to nobody.
        (Path(cfg.pki_dir) / "crl.pem").chmod(0o644)
        return True
    # Local regeneration reaches nothing off-box, so a failure is a defect
    # rather than a transient.
    # In the message, not a field: the console log format does not show fields.
    logger.error(f"CRL regeneration failed: {(result.stderr or '').strip()}")
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
        crl = _fetch_one(manager, cfg.secrets_provider, cfg.secrets_crl_path, "CRL")
        if crl is None:
            return False
        # A CRL the running CA did not sign makes OpenVPN refuse every client.
        if problem := crl_problem(crl, cfg.pki_dir / "ca.crt"):
            logger.error(f"Fetched CRL rejected, keeping the one on disk: {problem}")
            return False
        write_file_atomic(cfg.pki_dir / "crl.pem", crl, 0o644)
        return True
    finally:
        try:
            import asyncio

            asyncio.run(manager.close())
        except Exception as e:
            logger.debug(f"Secrets provider close failed: {e}")


def crl_refresher(cfg):
    """How to refresh the CRL for this PKI mode, or None when it cannot be.

    Local PKI regenerates from its own CA. External PKI re-fetches from the
    provider, because the CA key is not here. Gating the refresher on local mode
    - as it was - left external deployments serving the startup CRL forever, so
    an upstream revocation took effect only on a restart, silently.

    Returns (callable, description) or None.
    """
    if cfg.pki_mode != "external":
        return regenerate_local_crl, "regenerated from the local CA"
    if not cfg.secrets_crl_path:
        return None
    return refetch_external_crl, "re-fetched from the secrets provider"


def start_crl_refresh(cfg, proc_manager, interval_hours: float = 24) -> None:
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
                before = revoked_serials(cfg.pki_dir)
                if refresh(cfg):
                    logger.info("CRL refreshed successfully")
                    # OpenVPN re-reads the CRL per handshake, so a reload only
                    # ends a newly revoked session early, and drops all others.
                    newly = revoked_serials(cfg.pki_dir) - before
                    if newly:
                        logger.info("CRL revokes new certificates", count=len(newly))
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
