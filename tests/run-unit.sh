#!/usr/bin/env bash
#  Project:      culvert
#  File:         run-unit.sh
#  Purpose:      Run unit tests
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#===============================================================================
# Logging
#===============================================================================
log_info()  { echo -e "\033[0;32m[INFO]\033[0m $*"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }

#===============================================================================
# Check Dependencies
#===============================================================================
check_uv() {
    if ! command -v uv >/dev/null 2>&1; then
        log_error "uv not found. Install with:"
        log_error "  curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
}

#===============================================================================
# Main
#===============================================================================
main() {
    check_uv

    log_info "Running unit tests..."
    echo ""

    cd "${SCRIPT_DIR}/.."

    if [[ "${1:-}" == "--verbose" ]] || [[ "${1:-}" == "-v" ]]; then
        uv run --frozen --extra dev pytest tests/unit -v
    else
        uv run --frozen --extra dev pytest tests/unit
    fi
}

main "$@"
