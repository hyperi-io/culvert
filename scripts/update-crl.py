#!/usr/bin/env python3
#  Project:      culvert
#  File:         update-crl.py
#  Purpose:      Update certificate revocation list
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Update Certificate Revocation List.

Run periodically (e.g., via cron or entrypoint) to ensure CRL doesn't expire.

Usage: update-crl
"""

import os
import subprocess
import sys
from pathlib import Path

from scalo.logger import logger

# ===============================================================================
# Configuration
# ===============================================================================

PKI_DIR = Path("/etc/vpn/pki")
EASYRSA = Path("/usr/share/easy-rsa")


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
    )
    if result.returncode == 0:
        # Output is like: nextUpdate=Dec 20 12:00:00 2025 GMT
        for line in result.stdout.strip().split("\n"):
            if "nextUpdate=" in line:
                return line.split("=", 1)[1]
    return "unknown"


def update_crl() -> None:
    """Update the Certificate Revocation List."""
    logger.info("Updating CRL...")

    # Set up environment for easy-rsa
    env = os.environ.copy()
    env.update(
        {
            "EASYRSA": str(EASYRSA),
            "EASYRSA_PKI": str(PKI_DIR),
            "EASYRSA_BATCH": "1",
        }
    )

    # Generate CRL
    result = subprocess.run(
        ["./easyrsa", "gen-crl"],
        cwd=EASYRSA,
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        logger.error(f"Failed to update CRL: {result.stderr}")
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
    if not PKI_DIR.exists():
        logger.error("PKI directory not found. Initialize PKI first.")
        sys.exit(1)

    if not (PKI_DIR / "ca.crt").exists():
        logger.error("CA certificate not found. Initialize PKI first.")
        sys.exit(1)

    update_crl()


if __name__ == "__main__":
    main()
