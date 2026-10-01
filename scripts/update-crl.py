#!/usr/bin/env python3
#  Project:      culvert
#  File:         update-crl.py
#  Purpose:      Update certificate revocation list
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Update Certificate Revocation List.

Run periodically (e.g., via cron or entrypoint) to ensure CRL doesn't expire.

Usage: update-crl
"""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

# Allow importing lib/ modules from scripts directory (container and dev paths)
for _scripts_path in ["/etc/vpn/scripts", str(Path(__file__).parent)]:
    if _scripts_path not in sys.path:
        sys.path.insert(0, _scripts_path)

from lib.config import Config  # noqa: E402
from lib.pki import regenerate_local_crl  # noqa: E402
from scalo.logger import logger  # noqa: E402

# ===============================================================================
# Configuration
# ===============================================================================

PKI_DIR = Path("/etc/vpn/pki")


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


def update_crl(crl_days: int) -> None:
    """Regenerate the CRL through the shared PKI library and report its expiry."""
    logger.info("Updating CRL...")

    # The failure, with Easy-RSA's stderr, is logged by the library.
    if not regenerate_local_crl(SimpleNamespace(pki_dir=PKI_DIR, crl_days=crl_days)):
        sys.exit(1)

    crl_path = PKI_DIR / "crl.pem"
    expiry = get_crl_expiry()

    logger.info("CRL updated successfully")
    logger.info(f"  CRL file: {crl_path}")
    logger.info(f"  Expiry: {expiry}")


# ===============================================================================
# Main
# ===============================================================================


def main() -> None:
    """Regenerate the CRL from the local PKI."""
    if not PKI_DIR.exists():
        logger.error("PKI directory not found. Initialize PKI first.")
        sys.exit(1)

    if not (PKI_DIR / "ca.crt").exists():
        logger.error("CA certificate not found. Initialize PKI first.")
        sys.exit(1)

    update_crl(Config.from_settings().crl_days)


if __name__ == "__main__":
    main()
