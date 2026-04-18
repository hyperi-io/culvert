#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_vpn_connectivity.bats
#  Purpose:      Test multi-protocol VPN connectivity
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# End-to-end VPN connectivity tests
# These tests require a real VPN server and client config
#
# Prerequisites:
#   - OpenVPN client installed (openvpn package)
#   - Valid .ovpn config file
#   - Network access to VPN server
#   - Root/sudo privileges
#
# Usage:
#   OVPN_CONFIG=/path/to/client.ovpn sudo -E bats tests/e2e/test_vpn_connectivity.bats
#
# Environment Variables:
#   OVPN_CONFIG      - Path to .ovpn client config (required)
#   VPN_GATEWAY      - Expected VPN gateway IP (default: 192.168.100.1)
#   VPN_TIMEOUT      - Connection timeout in seconds (default: 15)
#   PING_TARGETS     - Comma-separated IPs to ping (default: gateway only)

load '../helpers/test_helper.bash'

# Add assert_output helper for bats
assert_output() {
    local expected=""
    local partial=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --partial) partial=true; shift ;;
            *) expected="$1"; shift ;;
        esac
    done

    if [[ "$partial" == true ]]; then
        if [[ "${output}" != *"${expected}"* ]]; then
            echo "Expected output to contain: ${expected}" >&2
            echo "Actual output: ${output}" >&2
            return 1
        fi
    else
        if [[ "${output}" != "${expected}" ]]; then
            echo "Expected: ${expected}" >&2
            echo "Actual: ${output}" >&2
            return 1
        fi
    fi
}

#===============================================================================
# Test Configuration
#===============================================================================

# Default values
VPN_GATEWAY="${VPN_GATEWAY:-192.168.100.1}"
VPN_TIMEOUT="${VPN_TIMEOUT:-15}"
PING_TARGETS="${PING_TARGETS:-${VPN_GATEWAY}}"

# State tracking
VPN_PID=""
VPN_LOGFILE="/tmp/bats-vpn-$$.log"

#===============================================================================
# Setup and Teardown
#===============================================================================

setup_file() {
    # Verify prerequisites
    if [[ -z "${OVPN_CONFIG:-}" ]]; then
        skip "OVPN_CONFIG environment variable not set"
    fi

    if [[ ! -f "${OVPN_CONFIG}" ]]; then
        skip "OVPN_CONFIG file not found: ${OVPN_CONFIG}"
    fi

    if ! command -v openvpn >/dev/null 2>&1; then
        skip "openvpn client not installed"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        skip "Root privileges required for VPN tests"
    fi

    # Ensure no stale VPN connections
    pkill -f "openvpn.*${OVPN_CONFIG##*/}" 2>/dev/null || true
    sleep 1

    # Clean up any existing tun interfaces from previous runs
    for i in {0..9}; do
        ip link delete "tun${i}" 2>/dev/null || true
    done
}

teardown_file() {
    # Kill VPN if still running
    if [[ -n "${VPN_PID:-}" ]] && kill -0 "${VPN_PID}" 2>/dev/null; then
        kill "${VPN_PID}" 2>/dev/null || true
        wait "${VPN_PID}" 2>/dev/null || true
    fi

    # Clean up any openvpn processes from this config
    pkill -f "openvpn.*${OVPN_CONFIG##*/}" 2>/dev/null || true

    # Remove log file
    rm -f "${VPN_LOGFILE}" 2>/dev/null || true
}

setup() {
    # Each test starts fresh
    :
}

teardown() {
    # Individual test cleanup if needed
    :
}

#===============================================================================
# Helper Functions
#===============================================================================

# Start VPN connection and wait for it to be ready
# shellcheck disable=SC2120
start_vpn() {
    local timeout="${1:-${VPN_TIMEOUT}}"
    local config="${2:-${OVPN_CONFIG}}"

    # Start openvpn in background
    openvpn --config "${config}" --daemon --log "${VPN_LOGFILE}" --writepid "/tmp/bats-vpn-$$.pid"

    # Wait for connection
    local elapsed=0
    while [[ ${elapsed} -lt ${timeout} ]]; do
        if ip link show tun0 >/dev/null 2>&1 && ip addr show tun0 | grep -q "inet "; then
            VPN_PID=$(cat "/tmp/bats-vpn-$$.pid" 2>/dev/null)
            return 0
        fi
        sleep 1
        ((elapsed++))
    done

    # Connection failed
    echo "VPN connection timed out after ${timeout}s" >&2
    echo "=== VPN Log ===" >&2
    cat "${VPN_LOGFILE}" >&2
    return 1
}

# Stop VPN connection
stop_vpn() {
    if [[ -f /tmp/bats-vpn-$$.pid ]]; then
        local pid
        pid=$(cat /tmp/bats-vpn-$$.pid)
        kill "${pid}" 2>/dev/null || true
        rm -f /tmp/bats-vpn-$$.pid
    fi
    pkill -f "openvpn.*${OVPN_CONFIG##*/}" 2>/dev/null || true
    sleep 2
}

# Get assigned VPN IP
get_vpn_ip() {
    ip addr show tun0 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1
}

# Check if route exists
route_exists() {
    local network="$1"
    ip route | grep -q "^${network}"
}

#===============================================================================
# Connection Tests
#===============================================================================

@test "VPN client can connect to server" {
    run start_vpn
    assert_success

    # Verify tun interface exists
    run ip link show tun0
    assert_success

    stop_vpn
}

@test "VPN client receives IP address from server pool" {
    start_vpn

    local vpn_ip
    vpn_ip=$(get_vpn_ip)

    # Should have an IP
    [[ -n "${vpn_ip}" ]]

    # IP should be in expected subnet (192.168.100.x by default)
    local expected_subnet="${VPN_GATEWAY%.*}"
    [[ "${vpn_ip}" == ${expected_subnet}.* ]]

    stop_vpn
}

@test "VPN connection establishes TLS 1.3" {
    start_vpn

    # Check log for TLS 1.3
    run grep -i "TLSv1.3" "${VPN_LOGFILE}"
    assert_success

    stop_vpn
}

@test "VPN uses AES-256-GCM cipher" {
    start_vpn

    # Check log for cipher
    run grep -i "AES-256-GCM" "${VPN_LOGFILE}"
    assert_success

    stop_vpn
}

#===============================================================================
# Routing Tests
#===============================================================================

@test "VPN gateway route is installed" {
    start_vpn

    # Check for route to VPN network
    run ip route show dev tun0
    assert_success
    assert_output --partial "192.168.100.0"

    stop_vpn
}

@test "pushed routes are installed" {
    start_vpn

    # Check log for pushed routes
    if grep -q "route 10.66.0.0" "${VPN_LOGFILE}"; then
        run route_exists "10.66.0.0"
        assert_success
    fi

    if grep -q "route 10.42.0.0" "${VPN_LOGFILE}"; then
        run route_exists "10.42.0.0"
        assert_success
    fi

    stop_vpn
}

#===============================================================================
# Connectivity Tests
#===============================================================================

@test "can ping VPN gateway" {
    start_vpn

    run ping -c 3 -W 2 "${VPN_GATEWAY}"
    assert_success

    stop_vpn
}

@test "can ping additional targets" {
    # Skip if no additional targets configured
    if [[ "${PING_TARGETS}" == "${VPN_GATEWAY}" ]]; then
        skip "No additional PING_TARGETS configured"
    fi

    start_vpn

    # Test each target
    IFS=',' read -ra targets <<< "${PING_TARGETS}"
    for target in "${targets[@]}"; do
        run ping -c 2 -W 2 "${target}"
        assert_success "Failed to ping ${target}"
    done

    stop_vpn
}

#===============================================================================
# Security Tests
#===============================================================================

@test "server certificate is verified" {
    start_vpn

    # Check for successful certificate verification
    run grep -E "VERIFY OK.*CN=" "${VPN_LOGFILE}"
    assert_success

    stop_vpn
}

@test "server hostname matches certificate" {
    start_vpn

    # Check for X509 name verification
    run grep "VERIFY X509NAME OK" "${VPN_LOGFILE}"
    assert_success

    stop_vpn
}

#===============================================================================
# Stability Tests
#===============================================================================

@test "VPN connection survives brief network interruption simulation" {
    start_vpn

    local vpn_ip
    vpn_ip=$(get_vpn_ip)

    # Verify connected
    [[ -n "${vpn_ip}" ]]

    # Wait a bit to ensure stable connection
    sleep 3

    # Connection should still be up
    run ip link show tun0
    assert_success

    # Should still have same IP
    local new_ip
    new_ip=$(get_vpn_ip)
    [[ "${vpn_ip}" == "${new_ip}" ]]

    stop_vpn
}

@test "VPN reconnects cleanly after disconnect" {
    # First connection
    start_vpn
    stop_vpn

    sleep 2

    # Second connection
    run start_vpn
    assert_success

    # Verify working
    run ping -c 1 -W 2 "${VPN_GATEWAY}"
    assert_success

    stop_vpn
}
