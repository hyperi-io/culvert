#!/usr/bin/env bats
#  Project:      culvert
#  File:         test_proxy_config.bats
#  Purpose:      Test proxy configuration
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

setup_file() {
    echo "Building and starting test container for proxy tests..." >&3
    build_test_container
    start_test_container
    wait_for_container_ready 60
}

teardown_file() {
    cleanup_test_container
}

#===============================================================================
# Proxy Option Parsing Tests
#===============================================================================

@test "generate-client accepts --proxy option" {
    run container_exec generate-client proxytest1 --proxy proxy.corp.com:8080
    assert_success
}

@test "generate-client validates proxy format" {
    run container_exec generate-client proxytest-invalid --proxy "invalid-proxy"
    assert_failure
    assert_contains "${output}" "Invalid proxy format"
}

@test "generate-client accepts --proxy-auth option" {
    run container_exec generate-client proxytest2 --proxy proxy.corp.com:3128 --proxy-auth
    assert_success
}

#===============================================================================
# Proxy Config Generation Tests
#===============================================================================

@test "proxy option generates four config files" {
    container_exec generate-client proxytest3 --proxy squid.internal:3128

    # Standard configs
    run container_exec test -f /etc/vpn/clients/proxytest3-udp-split.ovpn
    assert_success
    run container_exec test -f /etc/vpn/clients/proxytest3-udp-full.ovpn
    assert_success

    # Proxy configs
    run container_exec test -f /etc/vpn/clients/proxytest3-proxy-split.ovpn
    assert_success
    run container_exec test -f /etc/vpn/clients/proxytest3-proxy-full.ovpn
    assert_success
}

@test "proxy config contains http-proxy directive" {
    container_exec generate-client proxytest4 --proxy webproxy.local:8888

    config=$(container_exec cat /etc/vpn/clients/proxytest4-proxy-split.ovpn)
    assert_contains "${config}" "http-proxy webproxy.local 8888"
}

@test "proxy config contains http-proxy-retry directive" {
    container_exec generate-client proxytest5 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest5-proxy-full.ovpn)
    assert_contains "${config}" "http-proxy-retry"
}

@test "proxy config uses TCP only (no UDP)" {
    container_exec generate-client proxytest6 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest6-proxy-split.ovpn)
    # Should have TCP remote
    assert_contains "${config}" "tcp"
    # Should NOT have UDP fallback line for proxy mode
    if echo "${config}" | grep -q "remote.*udp"; then
        # If UDP exists, it should not be in the proxy config for remote lines
        # (comments are ok)
        lines_with_udp=$(echo "${config}" | grep "^remote.*udp" || true)
        [ -z "${lines_with_udp}" ]
    fi
}

@test "proxy config connects via port 443" {
    container_exec generate-client proxytest7 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest7-proxy-split.ovpn)
    assert_contains "${config}" "443 tcp"
}

@test "standard config does not contain http-proxy directive" {
    container_exec generate-client proxytest8 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest8-udp-split.ovpn)
    if echo "${config}" | grep -q "^http-proxy "; then
        return 1
    fi
}

#===============================================================================
# Proxy Authentication Tests
#===============================================================================

@test "proxy config with auth contains authentication hints" {
    container_exec generate-client proxytest9 --proxy proxy:8080 --proxy-auth

    config=$(container_exec cat /etc/vpn/clients/proxytest9-proxy-split.ovpn)
    assert_contains "${config}" "http-proxy-option AGENT"
}

@test "proxy config without auth has commented auth instructions" {
    container_exec generate-client proxytest10 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest10-proxy-split.ovpn)
    assert_contains "${config}" "Add proxy authentication if needed"
}

#===============================================================================
# Config Content Validation
#===============================================================================

@test "proxy split config does not contain redirect-gateway" {
    container_exec generate-client proxytest11 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest11-proxy-split.ovpn)
    if echo "${config}" | grep -q "^redirect-gateway"; then
        return 1
    fi
}

@test "proxy full config contains redirect-gateway" {
    container_exec generate-client proxytest12 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest12-proxy-full.ovpn)
    assert_contains "${config}" "redirect-gateway def1 bypass-dhcp"
}

@test "proxy config contains embedded certificates" {
    container_exec generate-client proxytest13 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest13-proxy-split.ovpn)
    assert_contains "${config}" "<ca>"
    assert_contains "${config}" "</ca>"
    assert_contains "${config}" "<cert>"
    assert_contains "${config}" "</cert>"
    assert_contains "${config}" "<key>"
    assert_contains "${config}" "</key>"
    assert_contains "${config}" "<tls-crypt-v2>"
    assert_contains "${config}" "</tls-crypt-v2>"
}

@test "proxy config maintains TLS 1.3 requirement" {
    container_exec generate-client proxytest14 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest14-proxy-split.ovpn)
    assert_contains "${config}" "tls-version-min 1.3"
}

@test "proxy config maintains CNSA 2.0 ciphers" {
    container_exec generate-client proxytest15 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest15-proxy-split.ovpn)
    assert_contains "${config}" "AES-256-GCM"
}

#===============================================================================
# Mode Description Tests
#===============================================================================

@test "proxy config indicates PROXY MODE in header" {
    container_exec generate-client proxytest16 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest16-proxy-split.ovpn)
    assert_contains "${config}" "PROXY MODE"
}

@test "standard config does not indicate proxy mode" {
    container_exec generate-client proxytest17 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest17-udp-split.ovpn)
    if echo "${config}" | grep -q "PROXY MODE"; then
        return 1
    fi
}
