#!/usr/bin/env bash
#  Project:      hyperi-vpn
#  File:         run-e2e.sh
#  Purpose:      Run end-to-end tests
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/e2e/config.env"

#===============================================================================
# Logging
#===============================================================================
log_info()  { echo -e "\033[0;32m[INFO]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
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

    if ! command -v openvpn >/dev/null 2>&1; then
        log_error "OpenVPN client not found"
        log_error "Install with: sudo apt install openvpn (Ubuntu) or brew install openvpn (macOS)"
        missing=1
    fi

    if ! command -v ssh >/dev/null 2>&1; then
        log_error "SSH client not found"
        missing=1
    fi

    if [[ ${missing} -eq 1 ]]; then
        exit 1
    fi
}

#===============================================================================
# Check Configuration
#===============================================================================
check_config() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "E2E configuration not found: ${CONFIG_FILE}"
        log_error ""
        log_error "Create config from example:"
        log_error "  cp ${SCRIPT_DIR}/e2e/config.env.example ${CONFIG_FILE}"
        log_error "  vim ${CONFIG_FILE}"
        exit 1
    fi

    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"

    if [[ -z "${E2E_VPN_HOST:-}" ]]; then
        log_error "E2E_VPN_HOST not set in ${CONFIG_FILE}"
        exit 1
    fi
}

#===============================================================================
# Pre-flight Checks
#===============================================================================
preflight_checks() {
    log_info "Running pre-flight checks..."

    # Check if we can reach the test VM
    log_info "  Checking connectivity to ${E2E_VPN_HOST}..."
    if ! ping -c 1 -W 3 "${E2E_VPN_HOST}" >/dev/null 2>&1; then
        log_warn "  Cannot ping ${E2E_VPN_HOST} - this may be normal if ICMP is blocked"
    fi

    # Check SSH connectivity
    log_info "  Checking SSH access..."
    if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${E2E_SSH_USER:-root}@${E2E_VPN_HOST}" "echo ok" >/dev/null 2>&1; then
        log_error "  Cannot SSH to ${E2E_VPN_HOST}"
        log_error "  Ensure you have SSH access to the test VM"
        exit 1
    fi
    log_info "  SSH access: OK"

    # Check if VPN container is running
    log_info "  Checking VPN container..."
    if ! ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${E2E_SSH_USER:-root}@${E2E_VPN_HOST}" \
        "docker ps --filter name=hyperi-vpn --format '{{.Status}}'" 2>/dev/null | grep -q "Up"; then
        log_error "  VPN container is not running on ${E2E_VPN_HOST}"
        log_error "  Start with: cd /opt/openvpn && docker compose up -d"
        exit 1
    fi
    log_info "  VPN container: Running"

    log_info "Pre-flight checks passed!"
    echo ""
}

#===============================================================================
# Cleanup
#===============================================================================
cleanup() {
    log_info "Cleaning up..."

    # Kill any OpenVPN processes started by tests
    sudo pkill -f "openvpn --config.*e2e-test" 2>/dev/null || true

    # Remove test client configs
    rm -rf /tmp/openvpn-e2e-test 2>/dev/null || true
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
    check_config
    preflight_checks

    # Ensure cleanup on exit
    trap cleanup EXIT

    log_info "Running E2E tests against ${E2E_VPN_HOST}..."
    log_warn "These tests require sudo for OpenVPN client"
    echo ""

    cd "${SCRIPT_DIR}"

    # Run tests
    if [[ -n "${verbose}" ]]; then
        sudo -E bats ${verbose} e2e/
    else
        sudo -E bats e2e/
    fi
}

main "$@"
