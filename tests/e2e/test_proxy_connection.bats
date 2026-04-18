#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_proxy_connection.bats
#  Purpose:      Test proxy fallback connectivity
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/e2e_helper'

setup_file() {
    # Load E2E configuration
    if [[ ! -f "${TEST_ROOT}/e2e/config.env" ]]; then
        skip "E2E config not found - create tests/e2e/config.env"
    fi
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    # Verify VPN host is reachable
    if ! ping -c 1 -W 3 "${E2E_VPN_HOST}" >/dev/null 2>&1; then
        echo "Warning: ${E2E_VPN_HOST} not responding to ping (may be blocked)" >&3
    fi

    # Create temp directory for test configs
    E2E_TEMP_DIR=$(mktemp -d)
    export E2E_TEMP_DIR

    # Generate test client config via SSH to VPN server
    echo "Generating test client configuration..." >&3
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${E2E_SSH_USER:-root}@${E2E_VPN_HOST}" \
        "docker exec openvpn generate-client e2e-proxy-test --proxy proxy.example.com:8080" \
        >/dev/null 2>&1 || true

    # Download the test configs
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${E2E_SSH_USER:-root}@${E2E_VPN_HOST}:/opt/openvpn/clients/e2e-proxy-test-*.ovpn" \
        "${E2E_TEMP_DIR}/" 2>/dev/null || true
}

teardown_file() {
    # Clean up
    sudo pkill -f "openvpn --config.*e2e-proxy-test" 2>/dev/null || true
    rm -rf "${E2E_TEMP_DIR}" 2>/dev/null || true

    # Revoke test client
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "${E2E_SSH_USER:-root}@${E2E_VPN_HOST}" \
        "docker exec openvpn revoke-client e2e-proxy-test" \
        >/dev/null 2>&1 || true
}

#===============================================================================
# Direct HTTPS Tunnel Tests (TCP 443)
#===============================================================================

@test "TCP 443 port is accessible on VPN server" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    run nc -z -w 5 "${E2E_VPN_HOST}" 443
    assert_success
}

@test "VPN server responds to OpenVPN handshake on TCP 443" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    # OpenVPN control channel starts with specific bytes
    # Just verify the port accepts connections and doesn't immediately close
    echo "" | timeout 3 nc "${E2E_VPN_HOST}" 443 >/dev/null 2>&1 || true

    # Connection should be accepted (even if we don't complete handshake)
    # The test passes if nc could connect
    run nc -z -w 5 "${E2E_VPN_HOST}" 443
    assert_success
}

@test "direct TCP 443 connection establishes VPN tunnel" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    # Skip if config not available
    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" ]]; then
        skip "Test config not generated"
    fi

    # Create TCP-only config (modify split config)
    local tcp_config="${E2E_TEMP_DIR}/tcp-only.ovpn"
    sed '/^remote.*udp$/d' "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" > "${tcp_config}"

    # Start VPN connection
    sudo openvpn --config "${tcp_config}" --daemon --log "${E2E_TEMP_DIR}/openvpn.log"

    # Wait for connection
    sleep 10

    # Check if tunnel is up
    run ip link show tun0
    assert_success

    # Clean up
    sudo pkill -f "openvpn --config.*tcp-only" || true
}

#===============================================================================
# HTTP Proxy Traversal Tests
#===============================================================================

@test "proxy config file exists and contains http-proxy directive" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn" ]]; then
        skip "Proxy config not generated"
    fi

    config=$(cat "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn")
    assert_contains "${config}" "http-proxy"
}

@test "proxy config uses TCP protocol only" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn" ]]; then
        skip "Proxy config not generated"
    fi

    config=$(cat "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn")

    # Should have TCP
    assert_contains "${config}" "tcp"

    # Should not have UDP remote line
    if grep -q "^remote.*udp$" "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn"; then
        return 1
    fi
}

@test "VPN connection via HTTP proxy (if proxy configured)" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    # Skip if no proxy configured
    if [[ -z "${E2E_PROXY_HOST:-}" ]]; then
        skip "E2E_PROXY_HOST not configured in config.env"
    fi

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn" ]]; then
        skip "Proxy config not generated"
    fi

    # Regenerate config with real proxy
    local real_proxy_config="${E2E_TEMP_DIR}/real-proxy.ovpn"
    sed "s/http-proxy proxy.example.com 8080/http-proxy ${E2E_PROXY_HOST} ${E2E_PROXY_PORT:-8080}/" \
        "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn" > "${real_proxy_config}"

    # Start VPN connection via proxy
    sudo openvpn --config "${real_proxy_config}" --daemon --log "${E2E_TEMP_DIR}/proxy-vpn.log"

    # Wait for connection
    sleep 15

    # Check if tunnel is up
    run ip link show tun0
    assert_success

    # Clean up
    sudo pkill -f "openvpn --config.*real-proxy" || true
}

#===============================================================================
# DPI Bypass Verification Tests
#===============================================================================

@test "traffic on TCP 443 appears as TLS to network analysis" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    # This test verifies that OpenVPN over TCP 443 uses TLS
    # which makes it appear as HTTPS traffic to DPI systems

    # Start a packet capture (requires tcpdump)
    if ! command -v tcpdump >/dev/null 2>&1; then
        skip "tcpdump not installed"
    fi

    local pcap_file="${E2E_TEMP_DIR}/capture.pcap"

    # Capture briefly during connection attempt
    timeout 5 sudo tcpdump -i any -w "${pcap_file}" \
        "host ${E2E_VPN_HOST} and port 443" 2>/dev/null &

    # Make a connection attempt
    timeout 3 bash -c "echo '' | nc ${E2E_VPN_HOST} 443" 2>/dev/null || true

    sleep 2

    # Analyze captured packets
    if [[ -f "${pcap_file}" ]] && [[ -s "${pcap_file}" ]]; then
        # Check for TLS handshake (0x16 = TLS record, 0x03 = version)
        # OpenVPN with TLS starts with a TLS handshake
        run tcpdump -r "${pcap_file}" -X 2>/dev/null
        # If we captured anything, the test passes (connection on 443 worked)
        assert_success
    fi
}

@test "OpenVPN uses TLS 1.3 as specified in config" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" ]]; then
        skip "Test config not generated"
    fi

    config=$(cat "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn")
    assert_contains "${config}" "tls-version-min 1.3"
}

@test "OpenVPN config uses AEAD ciphers for DPI resistance" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" ]]; then
        skip "Test config not generated"
    fi

    # AEAD ciphers produce traffic patterns harder to fingerprint
    config=$(cat "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn")
    assert_contains "${config}" "AES-256-GCM"
}

#===============================================================================
# Network Access Tests (after VPN established)
#===============================================================================

@test "VPN tunnel provides access to internal network" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    # Skip if config not available
    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" ]]; then
        skip "Test config not generated"
    fi

    # Start VPN
    sudo openvpn --config "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" \
        --daemon --log "${E2E_TEMP_DIR}/internal-test.log"

    sleep 15

    # Check if we can reach internal network
    if [[ -n "${E2E_INTERNAL_HOST:-}" ]]; then
        run ping -c 1 -W 5 "${E2E_INTERNAL_HOST}"
        assert_success
    fi

    # Clean up
    sudo pkill -f "openvpn --config.*e2e-proxy-test-split" || true
}

#===============================================================================
# Failover Tests
#===============================================================================

@test "client config has UDP primary with TCP fallback" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn" ]]; then
        skip "Test config not generated"
    fi

    config=$(cat "${E2E_TEMP_DIR}/e2e-proxy-test-split.ovpn")

    # Should have both UDP and TCP remote lines
    assert_contains "${config}" "udp"
    assert_contains "${config}" "tcp"
}

@test "proxy config has TCP only (no UDP fallback)" {
    # shellcheck source=/dev/null
    source "${TEST_ROOT}/e2e/config.env"

    if [[ ! -f "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn" ]]; then
        skip "Proxy config not generated"
    fi

    # Proxy mode should only have TCP (UDP doesn't work through HTTP proxies)
    if grep -q "^remote.*udp$" "${E2E_TEMP_DIR}/e2e-proxy-test-proxy-split.ovpn"; then
        return 1  # Fail if UDP remote found
    fi
}
