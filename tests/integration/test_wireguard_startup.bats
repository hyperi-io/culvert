#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_wireguard_startup.bats
#  Purpose:      Test WireGuard container startup and interface creation
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

setup_file() {
    build_test_container
}

teardown() {
    cleanup_test_container
}

@test "container starts in wireguard mode" {
    start_test_container -e "DFE_VPN_PROTOCOL=wireguard"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" wg show wg0
    assert_success
}

@test "container starts in both mode" {
    start_test_container -e "DFE_VPN_PROTOCOL=both"
    wait_for_container_ready 60
    # Both OpenVPN and WireGuard should be running
    run docker exec "${TEST_CONTAINER_NAME}" pgrep -x openvpn
    assert_success
    run docker exec "${TEST_CONTAINER_NAME}" wg show wg0
    assert_success
}

@test "WireGuard server keys are generated on first start" {
    start_test_container -e "DFE_VPN_PROTOCOL=wireguard"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" test -f /etc/vpn/pki/wireguard/server_private.key
    assert_success
    run docker exec "${TEST_CONTAINER_NAME}" test -f /etc/vpn/pki/wireguard/server_public.key
    assert_success
}

@test "WireGuard server keys have correct permissions" {
    start_test_container -e "DFE_VPN_PROTOCOL=wireguard"
    wait_for_container_ready 30
    # Private key should be 600
    run docker exec "${TEST_CONTAINER_NAME}" stat -c '%a' /etc/vpn/pki/wireguard/server_private.key
    assert_success
    [ "${output}" = "600" ]
}

@test "health endpoint responds in wireguard mode" {
    start_test_container -e "DFE_VPN_PROTOCOL=wireguard"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" curl -sf http://localhost:8080/health/live
    assert_success
}

@test "WireGuard config file is generated" {
    start_test_container -e "DFE_VPN_PROTOCOL=wireguard"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" test -f /etc/vpn/server/wg0.conf
    assert_success
    run docker exec "${TEST_CONTAINER_NAME}" grep -q "ListenPort = 51820" /etc/vpn/server/wg0.conf
    assert_success
}

@test "invalid protocol value is rejected" {
    start_test_container -e "DFE_VPN_PROTOCOL=invalid"
    sleep 5
    # Container should have exited with error
    run docker inspect --format='{{.State.Running}}' "${TEST_CONTAINER_NAME}"
    [ "${output}" = "false" ]
}
