#!/usr/bin/env python3
#  Project:      culvert
#  File:         update-crl.py
#  Purpose:      Update certificate revocation list
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Refresh the Certificate Revocation List now, rather than at the next refresh.

Local PKI regenerates the CRL from its CA. External PKI has no CA key here, so
it re-fetches the CRL from CULVERT_SECRETS_CRL_PATH, as the server's refresh
loop does.

Usage: update-crl
"""

import os
import signal
import subprocess
import sys
from pathlib import Path

# Allow importing lib/ modules from scripts directory (container and dev paths)
for _scripts_path in ["/etc/vpn/scripts", str(Path(__file__).parent)]:
    if _scripts_path not in sys.path:
        sys.path.insert(0, _scripts_path)

import scalo.logger  # noqa: E402
from lib.config import Config  # noqa: E402
from lib.pki import crl_refresher, revoked_serials  # noqa: E402
from scalo.logger import logger  # noqa: E402

# ===============================================================================
# Configuration
# ===============================================================================

PKI_DIR = Path("/etc/vpn/pki")

# The container's PID 1 is the server, whose SIGHUP handler reloads OpenVPN.
SERVER_PID = 1


# ===============================================================================
# CRL Functions
# ===============================================================================


def get_crl_expiry() -> str:
    """Get CRL expiry date."""
    crl_path = PKI_DIR / "crl.pem"
    if not crl_path.exists():
        return "N/A"

    result = subprocess.run(
        ["openssl", "crl", "-in", str(crl_path), "-noout", "-nextupdate"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode == 0:
        # Output is like: nextUpdate=Dec 20 12:00:00 2025 GMT
        for line in result.stdout.strip().split("\n"):
            if "nextUpdate=" in line:
                return line.split("=", 1)[1]
    return "unknown"


def reload_server(pid: int | None = None, proc: Path = Path("/proc")) -> bool:
    """SIGHUP the culvert server at pid, so sessions on newly revoked certs end.

    OpenVPN checks the CRL at the next handshake, so a session already up runs
    on until it renegotiates. The reload drops every connected client, as the
    background refresh does. Returns False when pid is not the culvert server.
    """
    pid = SERVER_PID if pid is None else pid
    try:
        argv = (proc / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    if not any(arg.endswith(b"entrypoint.py") for arg in argv) or b"server" not in argv:
        return False
    os.kill(pid, signal.SIGHUP)
    return True


def update_crl(cfg) -> None:
    """Refresh the CRL the way cfg's PKI mode allows, then report its expiry."""
    refresher = crl_refresher(cfg)
    if refresher is None:
        logger.error(
            "CULVERT_PKI_MODE=external with no CULVERT_SECRETS_CRL_PATH, so there"
            " is no CRL to fetch. Set it to where your CA publishes the CRL."
        )
        sys.exit(1)
    refresh, how = refresher
    logger.info(f"Updating CRL, {how}...")

    before = revoked_serials(cfg.pki_dir)
    # The library logs why a refresh failed.
    if not refresh(cfg):
        sys.exit(1)

    newly = revoked_serials(cfg.pki_dir) - before
    if newly:
        if reload_server():
            logger.info(
                "CRL revokes new certificates, reloaded the server", count=len(newly)
            )
        else:
            logger.warning(
                "CRL revokes new certificates, and no culvert server is PID 1 to"
                " reload. Their sessions last until they renegotiate.",
                count=len(newly),
            )

    crl_path = PKI_DIR / "crl.pem"
    expiry = get_crl_expiry()

    logger.info("CRL updated successfully")
    logger.info(f"  CRL file: {crl_path}")
    logger.info(f"  Expiry: {expiry}")


# ===============================================================================
# Main
# ===============================================================================


def main() -> None:
    """Refresh the CRL from the local CA or the external provider."""
    # culvert emits no spans, so no OTLP span exporter is started.
    scalo.logger.setup(otel_tracing=False)

    if not PKI_DIR.exists():
        logger.error("PKI directory not found. Initialize PKI first.")
        sys.exit(1)

    if not (PKI_DIR / "ca.crt").exists():
        logger.error("CA certificate not found. Initialize PKI first.")
        sys.exit(1)

    cfg = Config.from_settings()
    cfg.pki_dir = PKI_DIR
    update_crl(cfg)


if __name__ == "__main__":
    main()
