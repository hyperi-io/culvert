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

@test "generate-client issues a peer per device slot by default" {
    start_test_container -e "CULVERT_PROTOCOL=wireguard" -e "CULVERT_SERVER_CN=test.example.com"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgslots --protocol wireguard
    assert_success

    run docker exec "${TEST_CONTAINER_NAME}" ls /etc/vpn/clients/
    assert_success
    [[ "${output}" == *"wgslots-wg-split.conf"* ]]
    [[ "${output}" == *"wgslots-wg2-split.conf"* ]]

    # Distinct keys and addresses are what make the slots concurrently usable.
    run docker exec "${TEST_CONTAINER_NAME}" grep -h "^PrivateKey" /etc/vpn/clients/wgslots-wg-split.conf /etc/vpn/clients/wgslots-wg2-split.conf
    assert_success
    [[ "$(echo "${output}" | sort -u | wc -l)" -eq 2 ]]

    run docker exec "${TEST_CONTAINER_NAME}" grep -h "^Address" /etc/vpn/clients/wgslots-wg-split.conf /etc/vpn/clients/wgslots-wg2-split.conf
    assert_success
    [[ "$(echo "${output}" | sort -u | wc -l)" -eq 2 ]]
}

@test "opting out of sharing issues a single slot and drops duplicate-cn" {
    start_test_container -e "CULVERT_PROTOCOL=both" -e "CULVERT_SERVER_CN=test.example.com" \
        -e "CULVERT_ALLOW_SHARED_CLIENTS=false"
    wait_for_container_ready 60
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgexclusive --protocol wireguard
    assert_success

    run docker exec "${TEST_CONTAINER_NAME}" ls /etc/vpn/clients/
    assert_success
    [[ "${output}" == *"wgexclusive-wg-split.conf"* ]]
    [[ "${output}" != *"wgexclusive-wg2-split.conf"* ]]

    run docker exec "${TEST_CONTAINER_NAME}" grep -c '^duplicate-cn' /etc/vpn/server/server.conf
    assert_failure
}

@test "revoke-client removes every device slot" {
    start_test_container -e "CULVERT_PROTOCOL=wireguard" -e "CULVERT_SERVER_CN=test.example.com"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgrevoke --protocol wireguard
    assert_success

    run docker exec "${TEST_CONTAINER_NAME}" revoke-client --protocol wireguard wgrevoke
    assert_success

    # A slot left behind in allocations.json or the peers directory is a peer
    # the server config would rebuild, so revocation has to clear all of them.
    run docker exec "${TEST_CONTAINER_NAME}" ls /etc/vpn/pki/wireguard/peers/
    assert_success
    [[ "${output}" != *"wgrevoke"* ]]

    run docker exec "${TEST_CONTAINER_NAME}" grep -c wgrevoke /etc/vpn/pki/wireguard/allocations.json
    assert_failure
}

@test "WireGuard peer allocation creates allocations.json" {
    start_test_container -e "CULVERT_PROTOCOL=wireguard"
    wait_for_container_ready 30
    run docker exec "${TEST_CONTAINER_NAME}" generate-client --name wgalloc --protocol wireguard
    assert_success

    run docker exec "${TEST_CONTAINER_NAME}" test -f /etc/vpn/pki/wireguard/allocations.json
    assert_success
}
