#!/usr/bin/env bash
#  Project:      culvert
#  File:         run-integration.sh
#  Purpose:      Run integration tests
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
check_dependencies() {
    local missing=0

    if ! command -v bats >/dev/null 2>&1; then
        log_error "BATS not found"
        missing=1
    fi

    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker not found"
        missing=1
    fi

    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon not running or not accessible"
        missing=1
    fi

    if [[ ${missing} -eq 1 ]]; then
        exit 1
    fi
}

#===============================================================================
# Cleanup
#===============================================================================
cleanup() {
    log_info "Cleaning up test resources..."
    docker rm -f openvpn-test-* 2>/dev/null || true
    docker network rm openvpn-test-net 2>/dev/null || true
}

#===============================================================================
# Main
#===============================================================================
main() {
    local verbose=""

    if [[ "${1:-}" == "--verbose" ]] || [[ "${1:-}" == "-v" ]]; then
        verbose="--verbose-run"
    fi

    check_dependencies

    # Cleanup any leftover containers from previous runs
    cleanup

    log_info "Running integration tests..."
    log_info "This will build and test the container locally"
    echo ""

    cd "${SCRIPT_DIR}"

    # Run tests
    if [[ -n "${verbose}" ]]; then
        bats ${verbose} integration/
    else
        bats integration/
    fi

    local result=$?

    # Cleanup after tests
    cleanup

    exit ${result}
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

main "$@"
