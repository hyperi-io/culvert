#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_client_generation.bats
#  Purpose:      Test client config generation
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

setup_file() {
    echo "Building and starting test container..." >&3
    build_test_container
    start_test_container
    wait_for_container_ready 60
}

teardown_file() {
    cleanup_test_container
}

#===============================================================================
# Client Generation Tests
#===============================================================================

@test "generate-client creates all 6 config files" {
    run generate_test_client "testuser1"
    assert_success

    run client_configs_exist "testuser1"
    assert_success
}

@test "UDP split config file is created" {
    generate_test_client "testuser2"

    run container_exec test -f /etc/openvpn/clients/testuser2-udp-split.ovpn
    assert_success
}

@test "UDP full config file is created" {
    generate_test_client "testuser2a"

    run container_exec test -f /etc/openvpn/clients/testuser2a-udp-full.ovpn
    assert_success
}

@test "TCP split config file is created" {
    generate_test_client "testuser2b"

    run container_exec test -f /etc/openvpn/clients/testuser2b-tcp-split.ovpn
    assert_success
}

@test "TCP full config file is created" {
    generate_test_client "testuser2c"

    run container_exec test -f /etc/openvpn/clients/testuser2c-tcp-full.ovpn
    assert_success
}

@test "HTTPS split config file is created" {
    generate_test_client "testuser2d"

    run container_exec test -f /etc/openvpn/clients/testuser2d-https-split.ovpn
    assert_success
}

@test "HTTPS full config file is created" {
    generate_test_client "testuser3"

    run container_exec test -f /etc/openvpn/clients/testuser3-https-full.ovpn
    assert_success
}

@test "client certificate is created" {
    generate_test_client "testuser4"

    run container_exec test -f /etc/openvpn/pki/issued/testuser4.crt
    assert_success
}

@test "client private key is created" {
    generate_test_client "testuser5"

    run container_exec test -f /etc/openvpn/pki/private/testuser5.key
    assert_success
}

@test "client tls-crypt-v2 key is created" {
    generate_test_client "testuser6"

    run container_exec test -f /etc/openvpn/pki/private/testuser6-tc.key
    assert_success
}

@test "client private key has correct permissions" {
    generate_test_client "testuser7"

    run container_exec stat -c %a /etc/openvpn/pki/private/testuser7.key
    assert_success
    [ "${output}" = "600" ]
}

#===============================================================================
# UDP Config Content Tests
#===============================================================================

@test "UDP config contains client directive" {
    generate_test_client "configtest1"

    config=$(get_client_config "configtest1" "udp" "split")
    assert_contains "${config}" "client"
}

@test "UDP config contains server hostname" {
    generate_test_client "configtest2"

    config=$(get_client_config "configtest2" "udp" "split")
    assert_contains "${config}" "test-vpn.example.com"
}

@test "UDP config contains UDP remote entry" {
    generate_test_client "configtest3"

    config=$(get_client_config "configtest3" "udp" "split")
    assert_contains "${config}" "remote test-vpn.example.com 1194 udp"
}

#===============================================================================
# TCP Config Content Tests
#===============================================================================

@test "TCP config contains TCP remote entry with configured port" {
    generate_test_client "configtest4"

    config=$(get_client_config "configtest4" "tcp" "split")
    # Default TCP port is 443 (DPI bypass)
    assert_contains "${config}" "remote test-vpn.example.com 443 tcp"
}

#===============================================================================
# HTTPS Config Content Tests
#===============================================================================

@test "HTTPS config contains TCP 443 remote entry" {
    generate_test_client "configtest4a"

    config=$(get_client_config "configtest4a" "https" "split")
    assert_contains "${config}" "remote test-vpn.example.com 443 tcp"
}

#===============================================================================
# Full vs Split Tunnel Tests
#===============================================================================

@test "full tunnel config contains redirect-gateway" {
    generate_test_client "configtest5"

    config=$(get_client_config "configtest5" "udp" "full")
    assert_contains "${config}" "redirect-gateway def1 bypass-dhcp"
}

@test "split tunnel config does NOT contain redirect-gateway" {
    generate_test_client "configtest6"

    config=$(get_client_config "configtest6" "udp" "split")
    if [[ "${config}" == *"redirect-gateway"* ]]; then
        return 1
    fi
}

@test "TCP full tunnel config contains redirect-gateway" {
    generate_test_client "configtest6a"

    config=$(get_client_config "configtest6a" "tcp" "full")
    assert_contains "${config}" "redirect-gateway def1 bypass-dhcp"
}

@test "HTTPS full tunnel config contains redirect-gateway" {
    generate_test_client "configtest6b"

    config=$(get_client_config "configtest6b" "https" "full")
    assert_contains "${config}" "redirect-gateway def1 bypass-dhcp"
}

#===============================================================================
# Embedded Certificate Tests
#===============================================================================

@test "config contains embedded CA certificate" {
    generate_test_client "configtest7"

    config=$(get_client_config "configtest7" "udp" "split")
    assert_contains "${config}" "<ca>"
    assert_contains "${config}" "</ca>"
    assert_contains "${config}" "BEGIN CERTIFICATE"
}

@test "config contains embedded client certificate" {
    generate_test_client "configtest8"

    config=$(get_client_config "configtest8" "udp" "split")
    assert_contains "${config}" "<cert>"
    assert_contains "${config}" "</cert>"
}

@test "config contains embedded client key" {
    generate_test_client "configtest9"

    config=$(get_client_config "configtest9" "udp" "split")
    assert_contains "${config}" "<key>"
    assert_contains "${config}" "</key>"
}

@test "config contains embedded tls-crypt-v2 key" {
    generate_test_client "configtest10"

    config=$(get_client_config "configtest10" "udp" "split")
    assert_contains "${config}" "<tls-crypt-v2>"
    assert_contains "${config}" "</tls-crypt-v2>"
}

#===============================================================================
# Security Configuration Tests
#===============================================================================

@test "config contains TLS 1.3 requirement" {
    generate_test_client "configtest11"

    config=$(get_client_config "configtest11" "udp" "split")
    assert_contains "${config}" "tls-version-min 1.3"
}

@test "config contains CNSA 2.0 ciphers" {
    generate_test_client "configtest12"

    config=$(get_client_config "configtest12" "udp" "split")
    assert_contains "${config}" "AES-256-GCM"
}

#===============================================================================
# All Protocols Have Same Embedded Certs
#===============================================================================

@test "TCP config contains same embedded certificates as UDP" {
    generate_test_client "configtest13"

    udp_config=$(get_client_config "configtest13" "udp" "split")
    tcp_config=$(get_client_config "configtest13" "tcp" "split")
    https_config=$(get_client_config "configtest13" "https" "split")

    # All should contain embedded CA
    assert_contains "${udp_config}" "<ca>"
    assert_contains "${tcp_config}" "<ca>"
    assert_contains "${https_config}" "<ca>"

    # All should contain embedded client cert
    assert_contains "${udp_config}" "<cert>"
    assert_contains "${tcp_config}" "<cert>"
    assert_contains "${https_config}" "<cert>"

    # All should contain embedded client key
    assert_contains "${udp_config}" "<key>"
    assert_contains "${tcp_config}" "<key>"
    assert_contains "${https_config}" "<key>"

    # All should contain tls-crypt-v2
    assert_contains "${udp_config}" "<tls-crypt-v2>"
    assert_contains "${tcp_config}" "<tls-crypt-v2>"
    assert_contains "${https_config}" "<tls-crypt-v2>"
}

#===============================================================================
# Duplicate Client Tests
#===============================================================================

@test "cannot create duplicate client" {
    generate_test_client "duplicatetest"

    run generate_test_client "duplicatetest"
    assert_failure
    assert_contains "${output}" "already exists"
}

#===============================================================================
# Client Revocation Tests
#===============================================================================

@test "client can be revoked" {
    generate_test_client "revoketest1"

    run revoke_test_client "revoketest1"
    assert_success
}

@test "revoked client configs are removed" {
    generate_test_client "revoketest2"
    revoke_test_client "revoketest2"

    # Check that all 6 config files are removed
    run container_exec test -f /etc/openvpn/clients/revoketest2-udp-split.ovpn
    assert_failure
    run container_exec test -f /etc/openvpn/clients/revoketest2-udp-full.ovpn
    assert_failure
    run container_exec test -f /etc/openvpn/clients/revoketest2-tcp-split.ovpn
    assert_failure
    run container_exec test -f /etc/openvpn/clients/revoketest2-tcp-full.ovpn
    assert_failure
    run container_exec test -f /etc/openvpn/clients/revoketest2-https-split.ovpn
    assert_failure
    run container_exec test -f /etc/openvpn/clients/revoketest2-https-full.ovpn
    assert_failure
}

@test "revoked client certificate is in CRL" {
    generate_test_client "revoketest3"
    revoke_test_client "revoketest3"

    # CRL should be updated
    run container_exec test -f /etc/openvpn/pki/crl.pem
    assert_success

    # CRL should have content
    crl_size=$(container_exec wc -c /etc/openvpn/pki/crl.pem | awk '{print $1}')
    [ "${crl_size}" -gt 0 ]
}

@test "can create new client after revoking another" {
    generate_test_client "revoketest4"
    revoke_test_client "revoketest4"

    run generate_test_client "newclient1"
    assert_success
}
