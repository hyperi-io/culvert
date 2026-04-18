#!/usr/bin/env bats
#  Project:      hyperi-vpn
#  File:         test_startup.bats
#  Purpose:      Mandatory startup smoke test — container boots with defaults
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

setup_file() {
    build_test_container
    start_test_container
}

teardown_file() {
    cleanup_test_container
}

@test "smoke: container boots and reaches running state" {
    run docker inspect --format='{{.State.Running}}' "${TEST_CONTAINER_NAME}"
    assert_success
    [ "${output}" = "true" ]
}

@test "smoke: openvpn process starts within 60 seconds" {
    run wait_for_container_ready 60
    assert_success
}

@test "smoke: container reports healthy" {
    run container_is_healthy 30
    assert_success
}
