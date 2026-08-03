#!/usr/bin/env bats
#  Project:      culvert
#  File:         test_shared_storage.bats
#  Purpose:      Test shared PKI storage for scale-out
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

load '../helpers/test_helper'
load '../helpers/docker_helper'

# Override container names for multi-container tests
CONTAINER_PRIMARY="culvert-test-integration-shared-primary"
CONTAINER_SECONDARY="culvert-test-integration-shared-secondary"
SHARED_VOLUME="culvert-test-integration-shared-pki"
SHARED_CLIENTS_VOLUME="culvert-test-integration-shared-clients"

setup_file() {
    echo "Setting up shared storage test environment..." >&3

    # Clean up any existing containers
    docker rm -f "${CONTAINER_PRIMARY}" "${CONTAINER_SECONDARY}" 2>/dev/null || true
    docker volume rm "${SHARED_VOLUME}" "${SHARED_CLIENTS_VOLUME}" 2>/dev/null || true
    docker network rm "${TEST_NETWORK}" 2>/dev/null || true

    # Build test container
    echo "Building test container..." >&3
    build_test_container

    # Create shared volumes (simulates NFS/S3/EFS mount)
    docker volume create "${SHARED_VOLUME}" >/dev/null
    docker volume create "${SHARED_CLIENTS_VOLUME}" >/dev/null

    # Create test network
    docker network create "${TEST_NETWORK}" >/dev/null 2>&1 || true

    # Start PRIMARY container - this initializes PKI
    echo "Starting primary container (initializes PKI)..." >&3
    docker run -d \
        --name "${CONTAINER_PRIMARY}" \
        --network "${TEST_NETWORK}" \
        --cap-add NET_ADMIN \
        --device /dev/net/tun:/dev/net/tun \
        -e CULVERT_SERVER_CN=test-vpn.example.com \
        -e CULVERT_CA_CN="Test Shared VPN CA" \
        -v "${SHARED_VOLUME}:/etc/vpn/pki" \
        -v "${SHARED_CLIENTS_VOLUME}:/etc/vpn/clients" \
        "${TEST_IMAGE_NAME}" >/dev/null

    # Wait for primary to initialize PKI
    local count=0
    while [[ ${count} -lt 60 ]]; do
        if docker exec "${CONTAINER_PRIMARY}" pgrep -x openvpn >/dev/null 2>&1; then
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    if [[ ${count} -ge 60 ]]; then
        echo "Primary container failed to start" >&3
        docker logs "${CONTAINER_PRIMARY}" >&3
        return 1
    fi

    echo "Primary container ready, starting secondary..." >&3

    # Start SECONDARY container - uses existing PKI from shared volume
    docker run -d \
        --name "${CONTAINER_SECONDARY}" \
        --network "${TEST_NETWORK}" \
        --cap-add NET_ADMIN \
        --device /dev/net/tun:/dev/net/tun \
        -e CULVERT_SERVER_CN=test-vpn.example.com \
        -e CULVERT_CA_CN="Test Shared VPN CA" \
        -v "${SHARED_VOLUME}:/etc/vpn/pki" \
        -v "${SHARED_CLIENTS_VOLUME}:/etc/vpn/clients" \
        "${TEST_IMAGE_NAME}" >/dev/null

    # Wait for secondary
    count=0
    while [[ ${count} -lt 60 ]]; do
        if docker exec "${CONTAINER_SECONDARY}" pgrep -x openvpn >/dev/null 2>&1; then
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    echo "Both containers ready" >&3
}

teardown_file() {
    echo "Cleaning up shared storage test environment..." >&3
    docker rm -f "${CONTAINER_PRIMARY}" "${CONTAINER_SECONDARY}" 2>/dev/null || true
    docker volume rm "${SHARED_VOLUME}" "${SHARED_CLIENTS_VOLUME}" 2>/dev/null || true
    docker network rm "${TEST_NETWORK}" 2>/dev/null || true
}

#===============================================================================
# Shared PKI Tests
#===============================================================================

@test "both containers are running" {
    run docker inspect --format='{{.State.Running}}' "${CONTAINER_PRIMARY}"
    assert_success
    [ "${output}" = "true" ]

    run docker inspect --format='{{.State.Running}}' "${CONTAINER_SECONDARY}"
    assert_success
    [ "${output}" = "true" ]
}

@test "both containers have OpenVPN running" {
    run docker exec "${CONTAINER_PRIMARY}" pgrep -x openvpn
    assert_success

    run docker exec "${CONTAINER_SECONDARY}" pgrep -x openvpn
    assert_success
}

@test "both containers share the same CA certificate" {
    local ca_primary ca_secondary

    ca_primary=$(docker exec "${CONTAINER_PRIMARY}" cat /etc/vpn/pki/ca.crt | openssl x509 -noout -fingerprint -sha256)
    ca_secondary=$(docker exec "${CONTAINER_SECONDARY}" cat /etc/vpn/pki/ca.crt | openssl x509 -noout -fingerprint -sha256)

    [ "${ca_primary}" = "${ca_secondary}" ]
}

@test "both containers share the same server certificate" {
    local cert_primary cert_secondary

    cert_primary=$(docker exec "${CONTAINER_PRIMARY}" cat /etc/vpn/pki/issued/server.crt | openssl x509 -noout -fingerprint -sha256)
    cert_secondary=$(docker exec "${CONTAINER_SECONDARY}" cat /etc/vpn/pki/issued/server.crt | openssl x509 -noout -fingerprint -sha256)

    [ "${cert_primary}" = "${cert_secondary}" ]
}

@test "both containers share the same tls-crypt-v2 key" {
    local tc_primary tc_secondary

    tc_primary=$(docker exec "${CONTAINER_PRIMARY}" md5sum /etc/vpn/pki/tc.key | awk '{print $1}')
    tc_secondary=$(docker exec "${CONTAINER_SECONDARY}" md5sum /etc/vpn/pki/tc.key | awk '{print $1}')

    [ "${tc_primary}" = "${tc_secondary}" ]
}

#===============================================================================
# Client Certificate Sharing Tests
#===============================================================================

@test "client generated on primary is visible on secondary" {
    # Generate client on primary
    run docker exec "${CONTAINER_PRIMARY}" generate-client --name sharedtest1
    assert_success

    # Verify client cert exists on secondary
    run docker exec "${CONTAINER_SECONDARY}" test -f /etc/vpn/pki/issued/sharedtest1.crt
    assert_success
}

@test "client config generated on primary is visible on secondary" {
    # Generate client on primary
    docker exec "${CONTAINER_PRIMARY}" generate-client --name sharedtest2

    # Verify configs exist on secondary
    run docker exec "${CONTAINER_SECONDARY}" test -f /etc/vpn/clients/sharedtest2-udp-split.ovpn
    assert_success

    run docker exec "${CONTAINER_SECONDARY}" test -f /etc/vpn/clients/sharedtest2-udp-full.ovpn
    assert_success
}

@test "client generated on secondary uses same CA" {
    # Generate client on secondary
    run docker exec "${CONTAINER_SECONDARY}" generate-client --name sharedtest3
    assert_success

    # Verify client cert on primary is signed by the same CA
    run docker exec "${CONTAINER_PRIMARY}" test -f /etc/vpn/pki/issued/sharedtest3.crt
    assert_success

    # Verify using openssl
    run docker exec "${CONTAINER_PRIMARY}" openssl verify \
        -CAfile /etc/vpn/pki/ca.crt \
        /etc/vpn/pki/issued/sharedtest3.crt
    assert_success
}

#===============================================================================
# CRL Synchronization Tests
#===============================================================================

@test "CRL is shared between containers" {
    local crl_primary crl_secondary

    crl_primary=$(docker exec "${CONTAINER_PRIMARY}" md5sum /etc/vpn/pki/crl.pem | awk '{print $1}')
    crl_secondary=$(docker exec "${CONTAINER_SECONDARY}" md5sum /etc/vpn/pki/crl.pem | awk '{print $1}')

    [ "${crl_primary}" = "${crl_secondary}" ]
}

@test "client revoked on primary updates CRL visible to secondary" {
    # Generate and revoke client on primary
    docker exec "${CONTAINER_PRIMARY}" generate-client --name revoketest

    local crl_before
    crl_before=$(docker exec "${CONTAINER_SECONDARY}" md5sum /etc/vpn/pki/crl.pem | awk '{print $1}')

    docker exec "${CONTAINER_PRIMARY}" revoke-client revoketest

    local crl_after
    crl_after=$(docker exec "${CONTAINER_SECONDARY}" md5sum /etc/vpn/pki/crl.pem | awk '{print $1}')

    # CRL should have changed after revocation
    [ "${crl_before}" != "${crl_after}" ]
}

#===============================================================================
# Secondary Container Does Not Reinitialize PKI
#===============================================================================

@test "secondary container does not create new CA" {
    # Get CA creation time from primary's perspective
    local ca_mtime
    ca_mtime=$(docker exec "${CONTAINER_PRIMARY}" stat -c %Y /etc/vpn/pki/ca.crt)

    # Stop and restart secondary
    docker stop "${CONTAINER_SECONDARY}" >/dev/null
    docker start "${CONTAINER_SECONDARY}" >/dev/null

    # Wait for it to be ready
    local count=0
    while [[ ${count} -lt 30 ]]; do
        if docker exec "${CONTAINER_SECONDARY}" pgrep -x openvpn >/dev/null 2>&1; then
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    # CA modification time should not have changed
    local ca_mtime_after
    ca_mtime_after=$(docker exec "${CONTAINER_PRIMARY}" stat -c %Y /etc/vpn/pki/ca.crt)

    [ "${ca_mtime}" = "${ca_mtime_after}" ]
}

@test "secondary container logs show PKI already initialized" {
    # Restart secondary to capture startup logs
    docker stop "${CONTAINER_SECONDARY}" >/dev/null
    docker start "${CONTAINER_SECONDARY}" >/dev/null

    sleep 5

    # Check logs for indication that PKI was not reinitialized
    run docker logs "${CONTAINER_SECONDARY}" 2>&1
    assert_success

    # Should contain "already" or "exists" or similar message
    # (depends on entrypoint.sh implementation)
    if [[ "${output}" == *"PKI already initialized"* ]] || \
       [[ "${output}" == *"Using existing PKI"* ]] || \
       [[ "${output}" == *"Found existing"* ]]; then
        return 0
    fi

    # If it reinitializes, it should at least not overwrite
    # Verify CA wasn't regenerated by checking it's still valid for clients
    run docker exec "${CONTAINER_SECONDARY}" openssl verify \
        -CAfile /etc/vpn/pki/ca.crt \
        /etc/vpn/pki/issued/sharedtest1.crt
    assert_success
}
