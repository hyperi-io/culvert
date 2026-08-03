#!/usr/bin/env bats
#  Project:      culvert
#  File:         test_wireguard_client.bats
#  Purpose:      Test WireGuard client config generation
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

setup_file() {
    build_test_container
}

teardown() {
    cleanup_test_container
}

@test "generate-client creates WireGuard configs in wireguard mode" {
    start_test_container -e "CULVERT_PROTOCOL=wireguard" -e "CULVERT_SERVER_CN=test.example.com"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgonly --protocol wireguard
    assert_success

    # Check WireGuard configs were created
    run docker exec "${TEST_CONTAINER_NAME}" ls /etc/vpn/clients/
    assert_success
    [[ "${output}" == *"-wg-split.conf"* ]]
    [[ "${output}" == *"-wg-full.conf"* ]]
}

@test "generate-client creates both OpenVPN and WireGuard configs in both mode" {
    start_test_container -e "CULVERT_PROTOCOL=both" -e "CULVERT_SERVER_CN=test.example.com"
    wait_for_container_ready 60
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgboth --protocol all
    assert_success

    run docker exec "${TEST_CONTAINER_NAME}" ls /etc/vpn/clients/
    assert_success
    # Should have both .ovpn and .conf files
    [[ "${output}" == *".ovpn"* ]]
    [[ "${output}" == *"-wg-split.conf"* ]]
}

@test "WireGuard client config contains correct endpoint" {
    start_test_container -e "CULVERT_PROTOCOL=wireguard" -e "CULVERT_SERVER_CN=vpn.test.io"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgendpoint --protocol wireguard
    assert_success

    # Find the generated config and check endpoint
    # shellcheck disable=SC2012
    config_file=$(docker exec "${TEST_CONTAINER_NAME}" ls /etc/vpn/clients/ | grep 'wg-split.conf' | head -1)
    run docker exec "${TEST_CONTAINER_NAME}" grep "Endpoint" "/etc/vpn/clients/${config_file}"
    assert_success
    [[ "${output}" == *"vpn.test.io:51820"* ]]
}

@test "WireGuard peer allocation creates allocations.json" {
    start_test_container -e "CULVERT_PROTOCOL=wireguard"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgalloc --protocol wireguard
    assert_success

    run docker exec "${TEST_CONTAINER_NAME}" test -f /etc/vpn/pki/wireguard/allocations.json
    assert_success
}
