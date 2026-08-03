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
    run container_exec generate-client --name proxytest1 --proxy proxy.corp.com:8080
    assert_success
}

@test "generate-client validates proxy format" {
    run container_exec generate-client --name proxytest-invalid --proxy "invalid-proxy"
    assert_failure
    assert_contains "${output}" "Invalid proxy format"
}

@test "generate-client accepts --proxy-auth option" {
    run container_exec generate-client --name proxytest2 --proxy proxy.corp.com:3128 --proxy-auth
    assert_success
}

#===============================================================================
# Proxy Config Generation Tests
#===============================================================================

@test "proxy option generates four config files" {
    container_exec generate-client --name proxytest3 --proxy squid.internal:3128

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

@test "the proxy host and port reach the stunnel config" {
    container_exec generate-client --name proxytest4 --proxy webproxy.local:8888

    conf=$(container_exec cat /etc/vpn/clients/proxytest4-proxy-stunnel.conf)
    assert_contains "${conf}" "connect = webproxy.local:8888"
}

@test "both tunnel modes get a proxy config" {
    container_exec generate-client --name proxytest5 --proxy proxy:8080

    run container_exec test -f /etc/vpn/clients/proxytest5-proxy-split.ovpn
    assert_success
    run container_exec test -f /etc/vpn/clients/proxytest5-proxy-full.ovpn
    assert_success
}

@test "proxy config uses TCP only (no UDP)" {
    container_exec generate-client --name proxytest6 --proxy proxy:8080

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

@test "proxy stunnel config CONNECTs onward to port 443" {
    container_exec generate-client --name proxytest7 --proxy proxy:8080

    # The proxy is stunnel's business, not OpenVPN's, so the port that matters
    # is the one stunnel asks the proxy to CONNECT to. 443 is the only port a
    # corporate proxy reliably permits, which is why the HTTPS listener is the
    # target rather than the plain TCP one.
    conf=$(container_exec cat /etc/vpn/clients/proxytest7-proxy-stunnel.conf)
    assert_contains "${conf}" "connect = proxy:8080"
    assert_contains "${conf}" "protocol = connect"
    assert_contains "${conf}" "protocolHost = test-vpn.example.com:443"
}

@test "proxy OpenVPN config does not carry an http-proxy directive" {
    container_exec generate-client --name proxytest7b --proxy proxy:8080

    # It used to. OpenVPN's remote here is the LOCAL stunnel, so an http-proxy
    # line asked the corporate proxy to CONNECT to 127.0.0.1 - which no proxy
    # will do. The config looked plausible and could never have worked.
    config=$(container_exec cat /etc/vpn/clients/proxytest7b-proxy-split.ovpn)
    if echo "${config}" | grep -q "^http-proxy"; then
        return 1
    fi
    assert_contains "${config}" "remote 127.0.0.1 1195 tcp"
}

@test "proxy mode does not clobber the direct-HTTPS stunnel config" {
    container_exec generate-client --name proxytest7c --proxy proxy:8080

    # Both come from the same tcp-https branch and proxy runs second, so a
    # shared filename silently destroyed the direct config in the same run.
    direct=$(container_exec cat /etc/vpn/clients/proxytest7c-stunnel.conf)
    assert_contains "${direct}" "connect = test-vpn.example.com:443"
    if echo "${direct}" | grep -q "protocol = connect"; then
        return 1
    fi
}

@test "standard config does not contain http-proxy directive" {
    container_exec generate-client --name proxytest8 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest8-udp-split.ovpn)
    if echo "${config}" | grep -q "^http-proxy "; then
        return 1
    fi
}

#===============================================================================
# Proxy Authentication Tests
#===============================================================================

@test "proxy config with auth contains authentication placeholders" {
    container_exec generate-client --name proxytest9 --proxy proxy:8080 --proxy-auth

    conf=$(container_exec cat /etc/vpn/clients/proxytest9-proxy-stunnel.conf)
    assert_contains "${conf}" "protocolAuthentication = basic"
    assert_contains "${conf}" "protocolUsername"
}

@test "proxy config without auth has commented auth instructions" {
    container_exec generate-client --name proxytest10 --proxy proxy:8080

    conf=$(container_exec cat /etc/vpn/clients/proxytest10-proxy-stunnel.conf)
    assert_contains "${conf}" "Add proxy authentication if needed"
    # Commented, not active - an uninvited protocolUsername would break the
    # CONNECT against a proxy that wants no auth.
    if echo "${conf}" | grep -q "^protocolAuthentication"; then
        return 1
    fi
}

#===============================================================================
# Config Content Validation
#===============================================================================

@test "proxy split config does not contain redirect-gateway" {
    container_exec generate-client --name proxytest11 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest11-proxy-split.ovpn)
    if echo "${config}" | grep -q "^redirect-gateway"; then
        return 1
    fi
}

@test "proxy full config contains redirect-gateway" {
    container_exec generate-client --name proxytest12 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest12-proxy-full.ovpn)
    assert_contains "${config}" "redirect-gateway def1 bypass-dhcp"
}

@test "proxy config contains embedded certificates" {
    container_exec generate-client --name proxytest13 --proxy proxy:8080

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
    container_exec generate-client --name proxytest14 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest14-proxy-split.ovpn)
    assert_contains "${config}" "tls-version-min 1.3"
}

@test "proxy config maintains CNSA 2.0 ciphers" {
    container_exec generate-client --name proxytest15 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest15-proxy-split.ovpn)
    assert_contains "${config}" "AES-256-GCM"
}

#===============================================================================
# Mode Description Tests
#===============================================================================

@test "proxy config indicates PROXY MODE in header" {
    container_exec generate-client --name proxytest16 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest16-proxy-split.ovpn)
    assert_contains "${config}" "PROXY MODE"
}

@test "standard config does not indicate proxy mode" {
    container_exec generate-client --name proxytest17 --proxy proxy:8080

    config=$(container_exec cat /etc/vpn/clients/proxytest17-udp-split.ovpn)
    if echo "${config}" | grep -q "PROXY MODE"; then
        return 1
    fi
}
