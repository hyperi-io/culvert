#!/usr/bin/env bats
#  Project:      culvert
#  File:         test_container_startup.bats
#  Purpose:      Test container startup with defaults
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

setup_file() {
    # Build and start test container once for all tests in this file
    echo "Building test container..." >&3
    build_test_container
    start_test_container
    wait_for_container_ready 60
}

teardown_file() {
    # Clean up after all tests
    cleanup_test_container
}

#===============================================================================
# Container Startup Tests
#===============================================================================

@test "container starts with default configuration" {
    # Container was started in setup_file - verify it's running
    run docker inspect --format='{{.State.Running}}' "${TEST_CONTAINER_NAME}"
    assert_success
    [ "${output}" = "true" ]
}

@test "container is healthy after startup" {
    run container_is_healthy 10
    assert_success
}

@test "openvpn process is running" {
    run container_exec pgrep -x openvpn
    assert_success
}

#===============================================================================
# PKI Initialization Tests
#===============================================================================

@test "PKI is initialized on first startup" {
    run container_pki_initialized
    assert_success
}

@test "CA certificate is created" {
    run container_exec test -f /etc/vpn/pki/ca.crt
    assert_success
}

@test "server certificate is created" {
    run container_exec test -f /etc/vpn/pki/issued/server.crt
    assert_success
}

@test "server private key is created" {
    run container_exec test -f /etc/vpn/pki/private/server.key
    assert_success
}

@test "tls-crypt-v2 key is created" {
    run container_exec test -f /etc/vpn/pki/tc.key
    assert_success
}

@test "CRL is created" {
    run container_exec test -f /etc/vpn/pki/crl.pem
    assert_success
}

@test "server certificate is signed by CA" {
    run verify_container_server_cert
    assert_success
}

@test "private key has correct permissions (600)" {
    run container_exec stat -c %a /etc/vpn/pki/private/server.key
    assert_success
    [ "${output}" = "600" ]
}

#===============================================================================
# Server Configuration Tests
#===============================================================================

@test "server config file exists" {
    run container_exec test -f /etc/vpn/server/server.conf
    assert_success
}

@test "server config has correct protocol" {
    run container_exec grep "^proto udp" /etc/vpn/server/server.conf
    assert_success
}

@test "server config has correct port" {
    run container_exec grep "^port 1194" /etc/vpn/server/server.conf
    assert_success
}

@test "server config references PKI files" {
    local config
    config=$(get_server_config)

    assert_contains "${config}" "ca /etc/vpn/pki/ca.crt"
    assert_contains "${config}" "cert /etc/vpn/pki/issued/server.crt"
    assert_contains "${config}" "key /etc/vpn/pki/private/server.key"
}

#===============================================================================
# Network Configuration Tests
#===============================================================================

@test "tun device is available" {
    run container_exec test -c /dev/net/tun
    assert_success
}

@test "IP forwarding is enabled" {
    run container_exec cat /proc/sys/net/ipv4/ip_forward
    assert_success
    [ "${output}" = "1" ]
}

#===============================================================================
# Log Directory Tests
#===============================================================================

@test "log directory is created" {
    run container_exec test -d /var/log/vpn
    assert_success
}

@test "openvpn.log is created" {
    run container_exec test -f /var/log/vpn/openvpn.log
    assert_success
}
