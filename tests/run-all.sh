#!/usr/bin/env bash
#  Project:      hyperi-vpn
#  File:         run-all.sh
#  Purpose:      Run all test suites
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#===============================================================================
# Logging
#===============================================================================
log_info()  { echo -e "\033[0;32m[INFO]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }
log_header() { echo -e "\n\033[1;36m========== $* ==========\033[0m\n"; }

#===============================================================================
# Main
#===============================================================================
main() {
    local verbose=""
    local skip_e2e=""
    local failed=0

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -v|--verbose)
                verbose="--verbose"
                shift
                ;;
            --skip-e2e)
                skip_e2e="1"
                shift
                ;;
            -h|--help)
                echo "Usage: ${0} [options]"
                echo ""
                echo "Options:"
                echo "  -v, --verbose   Verbose test output"
                echo "  --skip-e2e      Skip E2E tests (require VPN infrastructure)"
                echo "  -h, --help      Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: ${1}"
                exit 1
                ;;
        esac
    done

    log_header "HyperI VPN Test Suite"

    #---------------------------------------------------------------------------
    # Unit Tests
    #---------------------------------------------------------------------------
    log_header "Unit Tests"

    if "${SCRIPT_DIR}/run-unit.sh" ${verbose}; then
        log_info "Unit tests: PASSED"
    else
        log_error "Unit tests: FAILED"
        failed=1
    fi

    #---------------------------------------------------------------------------
    # Integration Tests
    #---------------------------------------------------------------------------
    log_header "Integration Tests"

    if "${SCRIPT_DIR}/run-integration.sh" ${verbose}; then
        log_info "Integration tests: PASSED"
    else
        log_error "Integration tests: FAILED"
        failed=1
    fi

    #---------------------------------------------------------------------------
    # E2E Tests
    #---------------------------------------------------------------------------
    if [[ -z "${skip_e2e}" ]]; then
        log_header "End-to-End Tests"

        if [[ -f "${SCRIPT_DIR}/e2e/config.env" ]]; then
            if "${SCRIPT_DIR}/run-e2e.sh" ${verbose}; then
                log_info "E2E tests: PASSED"
            else
                log_error "E2E tests: FAILED"
                failed=1
            fi
        else
            log_warn "E2E tests skipped (config.env not found)"
            log_warn "Create config: cp tests/e2e/config.env.example tests/e2e/config.env"
        fi
    else
        log_warn "E2E tests skipped (--skip-e2e)"
    fi

    #---------------------------------------------------------------------------
    # Summary
    #---------------------------------------------------------------------------
    log_header "Test Summary"

    if [[ ${failed} -eq 0 ]]; then
        log_info "All tests PASSED"
        exit 0
    else
        log_error "Some tests FAILED"
        exit 1
    fi
}

main "$@"
