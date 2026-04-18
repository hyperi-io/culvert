#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_certificate_revocation.bats
#  Purpose:      Test CRL enforcement
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/e2e_helper'

REVOKE_TEST_CLIENT=""

setup_file() {
    load_e2e_config || skip "E2E config not found"
    ensure_test_vm_ready || skip "Test VM not accessible"
    vpn_container_running || skip "VPN container not running"

    # Generate a client specifically for revocation testing
    REVOKE_TEST_CLIENT=$(generate_e2e_test_client)
    export REVOKE_TEST_CLIENT
}

teardown_file() {
    disconnect_vpn
    # Client should already be revoked, but cleanup just in case
    revoke_e2e_test_client "${REVOKE_TEST_CLIENT}" 2>/dev/null || true
}

setup() {
    disconnect_vpn
}

teardown() {
    disconnect_vpn
}

#===============================================================================
# Pre-Revocation Tests
#===============================================================================

@test "client can connect before revocation" {
    run connect_vpn "${E2E_TEST_CLIENT_DIR}/${REVOKE_TEST_CLIENT}-split.ovpn"
    assert_success

    run ping_vpn_gateway
    assert_success
}

@test "client can reach internal network before revocation" {
    connect_vpn "${E2E_TEST_CLIENT_DIR}/${REVOKE_TEST_CLIENT}-split.ovpn"

    run ping -c 2 -W 2 "${E2E_INTERNAL_GATEWAY:-10.0.0.1}"
    assert_success
}

#===============================================================================
# Revocation Tests
#===============================================================================

@test "client certificate can be revoked" {
    disconnect_vpn

    run revoke_e2e_test_client "${REVOKE_TEST_CLIENT}"
    assert_success
}

@test "revoked client cannot establish new connection" {
    # Ensure client is revoked
    revoke_e2e_test_client "${REVOKE_TEST_CLIENT}" 2>/dev/null || true

    # Try to connect with revoked certificate
    # This should fail or timeout
    run connect_vpn "${E2E_TEST_CLIENT_DIR}/${REVOKE_TEST_CLIENT}-split.ovpn" 15
    assert_failure
}

@test "revoked client config files are removed from server" {
    revoke_e2e_test_client "${REVOKE_TEST_CLIENT}" 2>/dev/null || true

    run ssh_to_vpn "docker exec dfe-vpn test -f /etc/openvpn/clients/${REVOKE_TEST_CLIENT}-split.ovpn"
    assert_failure
}

#===============================================================================
# Post-Revocation - New Client Tests
#===============================================================================

@test "new client can be created after revocation" {
    NEW_CLIENT=$(generate_e2e_test_client)

    run connect_vpn "${E2E_TEST_CLIENT_DIR}/${NEW_CLIENT}-split.ovpn"
    assert_success

    run ping_vpn_gateway
    assert_success

    # Cleanup
    disconnect_vpn
    revoke_e2e_test_client "${NEW_CLIENT}" || true
}
