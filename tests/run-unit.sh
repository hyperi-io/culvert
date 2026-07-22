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
check_bats() {
    if ! command -v bats >/dev/null 2>&1; then
        log_error "BATS not found. Install with:"
        log_error "  macOS: brew install bats-core"
        log_error "  Ubuntu: sudo apt install bats"
        exit 1
    fi
}

#===============================================================================
# Main
#===============================================================================
main() {
    check_bats

    log_info "Running unit tests..."
    echo ""

    cd "${SCRIPT_DIR}"

    if [[ "${1:-}" == "--verbose" ]] || [[ "${1:-}" == "-v" ]]; then
        bats --verbose-run unit/
    else
        bats unit/
    fi
}

main "$@"
