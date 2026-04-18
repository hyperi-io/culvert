#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_vpn_connection.bats
#  Purpose:      Test full VPN connectivity
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/e2e_helper'

# Test client name (unique per test run)
TEST_CLIENT=""

setup_file() {
    echo "Loading E2E configuration..." >&3
    load_e2e_config || skip "E2E config not found"

    echo "Checking test VM accessibility..." >&3
    ensure_test_vm_ready || skip "Test VM not accessible"

    echo "Checking VPN container..." >&3
    vpn_container_running || skip "VPN container not running on test VM"

    # Generate a test client for this test run
    echo "Generating test client..." >&3
    TEST_CLIENT=$(generate_e2e_test_client)
    export TEST_CLIENT
}

teardown_file() {
    # Disconnect and cleanup
    disconnect_vpn
    if [[ -n "${TEST_CLIENT}" ]]; then
        revoke_e2e_test_client "${TEST_CLIENT}" || true
    fi
}

setup() {
    # Ensure we're disconnected before each test
    disconnect_vpn
}

teardown() {
    # Disconnect after each test
    disconnect_vpn
}

#===============================================================================
# Server Accessibility Tests
#===============================================================================

@test "VPN server responds on UDP port" {
    run test_udp_connectivity
    assert_success
}

@test "VPN server responds on TCP port" {
    run test_tcp_connectivity
    assert_success
}

#===============================================================================
# Split Tunnel Connection Tests
#===============================================================================

@test "can connect with split tunnel config" {
    run connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"
    assert_success
}

@test "split tunnel: tun0 interface is created" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run ip addr show tun0
    assert_success
}

@test "split tunnel: client gets IP in VPN range" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    client_ip=$(get_vpn_client_ip)
    assert_contains "${client_ip}" "10.8.0."
}

@test "split tunnel: can ping VPN gateway" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run ping_vpn_gateway
    assert_success
}

@test "split tunnel: default route is NOT through VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run test_split_tunnel
    assert_success
}

#===============================================================================
# Full Tunnel Connection Tests
#===============================================================================

@test "can connect with full tunnel config" {
    run connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-full.ovpn"
    assert_success
}

@test "full tunnel: all traffic routed through VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-full.ovpn"

    run test_full_tunnel
    assert_success
}

@test "full tunnel: can ping VPN gateway" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-full.ovpn"

    run ping_vpn_gateway
    assert_success
}

#===============================================================================
# Internal Network Access Tests
#===============================================================================
# Configure via environment:
#   E2E_INTERNAL_GATEWAY  (default: 10.0.0.1)  — routable internal host
#   E2E_INTERNAL_WEB_PORT (default: 8006)      — any TCP service to test
#   E2E_INTERNAL_SSH_PORT (default: 22)        — SSH port on the internal host

@test "can reach internal gateway via VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run ping -c 3 -W 2 "${E2E_INTERNAL_GATEWAY:-10.0.0.1}"
    assert_success
}

@test "can reach internal web port via VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run nc -z -w 5 "${E2E_INTERNAL_GATEWAY:-10.0.0.1}" "${E2E_INTERNAL_WEB_PORT:-8006}"
    assert_success
}

@test "can SSH to internal gateway via VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run nc -z -w 5 "${E2E_INTERNAL_GATEWAY:-10.0.0.1}" "${E2E_INTERNAL_SSH_PORT:-22}"
    assert_success
}

@test "internal web endpoint returns response over VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run curl -k -s -o /dev/null -w "%{http_code}" --max-time 10 \
        "https://${E2E_INTERNAL_GATEWAY:-10.0.0.1}:${E2E_INTERNAL_WEB_PORT:-8006}/"
    assert_success
    # Any HTTP status code means we reached the server; specific status is site-dependent
    assert_not_equal "${output}" "000"
}

#===============================================================================
# Internal Network Routing Tests
#===============================================================================

@test "route to internal network exists" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run ip route
    assert_contains "${output}" "${E2E_INTERNAL_NETWORK:-10.0.0.0/24}"
}

@test "can reach other hosts on internal network" {
    skip_if_not_set E2E_INTERNAL_TEST_HOST

    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"

    run ping -c 3 -W 2 "${E2E_INTERNAL_TEST_HOST}"
    assert_success
}

#===============================================================================
# DNS Tests
#===============================================================================

@test "DNS resolution works through VPN" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-full.ovpn"

    run test_vpn_dns "google.com"
    assert_success
}

#===============================================================================
# Reconnection Tests
#===============================================================================

@test "can reconnect after disconnect" {
    # First connection
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"
    ping_vpn_gateway

    # Disconnect
    disconnect_vpn
    sleep 2

    # Reconnect
    run connect_vpn "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn"
    assert_success

    run ping_vpn_gateway
    assert_success
}

#===============================================================================
# Protocol Fallback Tests
#===============================================================================

@test "client config contains UDP and TCP remotes" {
    config=$(cat "${E2E_TEST_CLIENT_DIR}/${TEST_CLIENT}-split.ovpn")

    assert_contains "${config}" "1194 udp"
    assert_contains "${config}" "443 tcp"
}

#===============================================================================
# Helper Functions
#===============================================================================

skip_if_not_set() {
    local var_name="${1}"
    local var_value
    eval "var_value=\${${var_name}:-}"

    if [[ -z "${var_value}" ]]; then
        skip "${var_name} not configured"
    fi
}
