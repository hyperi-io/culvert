#!/usr/bin/env bash
#  Project:      culvert
#  File:         docker_helper.bash
#  Purpose:      Docker container lifecycle helpers for tests
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Test container configuration
# Use a fixed name within a test file session - BATS_TEST_FILENAME provides consistency
# across all tests in a file (setup, teardown, test functions all share this)
if [[ -n "${BATS_TEST_FILENAME:-}" ]]; then
    # In BATS context - use test file basename for container name
    _test_file_base=$(basename "${BATS_TEST_FILENAME}" .bats)
    TEST_CONTAINER_NAME="openvpn-test-${_test_file_base}"
else
    # Outside BATS - use a fixed name for manual testing
    TEST_CONTAINER_NAME="openvpn-test-manual"
fi
TEST_IMAGE_NAME="culvert:test"
TEST_NETWORK="openvpn-test-net"

#===============================================================================
# Container Management
#===============================================================================

# Build test container image
build_test_container() {
    docker build -t "${TEST_IMAGE_NAME}" "${PROJECT_ROOT}" >/dev/null 2>&1
}

# Start test container
start_test_container() {
    local env_file="${1:-}"
    local extra_args=()

    if [[ -n "${env_file}" ]] && [[ -f "${env_file}" ]]; then
        extra_args+=(--env-file "${env_file}")
    fi

    # Create test network if not exists (always try to create, ignore if exists)
    docker network create "${TEST_NETWORK}" >/dev/null 2>&1 || true

    # Remove any existing container with same name
    docker rm -f "${TEST_CONTAINER_NAME}" >/dev/null 2>&1 || true

    docker run -d \
        --name "${TEST_CONTAINER_NAME}" \
        --network "${TEST_NETWORK}" \
        --cap-add NET_ADMIN \
        --device /dev/net/tun:/dev/net/tun \
        -e CULVERT_SERVER_CN=test-vpn.example.com \
        -e CULVERT_CA_CN="Test VPN CA" \
        "${extra_args[@]}" \
        "${TEST_IMAGE_NAME}"
}

# Stop and remove test container
stop_test_container() {
    docker rm -f "${TEST_CONTAINER_NAME}" >/dev/null 2>&1 || true
}

# Clean up all test resources
cleanup_test_container() {
    stop_test_container
    docker network rm "${TEST_NETWORK}" >/dev/null 2>&1 || true
    # Note: intentionally NOT deleting the image to speed up subsequent test runs
    # Run 'docker rmi culvert:test' manually if needed
}

# Check if container is healthy
container_is_healthy() {
    local timeout="${1:-60}"
    local count=0

    while [[ ${count} -lt ${timeout} ]]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "${TEST_CONTAINER_NAME}" 2>/dev/null || echo "none")

        case "${status}" in
            healthy)
                return 0
                ;;
            unhealthy)
                return 1
                ;;
            *)
                # Still starting or no healthcheck
                sleep 1
                count=$((count + 1))
                ;;
        esac
    done

    return 1
}

# Wait for container to be ready (healthcheck + OpenVPN running)
wait_for_container_ready() {
    local timeout="${1:-60}"
    local count=0

    # Debug output
    echo "# Waiting for container: ${TEST_CONTAINER_NAME}" >&3 2>/dev/null || true

    while [[ ${count} -lt ${timeout} ]]; do
        # Check if container exists first
        if ! docker inspect "${TEST_CONTAINER_NAME}" >/dev/null 2>&1; then
            echo "# Container ${TEST_CONTAINER_NAME} not found (attempt ${count})" >&3 2>/dev/null || true
            sleep 1
            count=$((count + 1))
            continue
        fi

        # Check container state
        local state
        state=$(docker inspect --format='{{.State.Status}}' "${TEST_CONTAINER_NAME}" 2>/dev/null)
        if [[ "${state}" != "running" ]]; then
            echo "# Container state: ${state} (attempt ${count})" >&3 2>/dev/null || true
            sleep 1
            count=$((count + 1))
            continue
        fi

        # Check if openvpn process is running
        local pgrep_result
        pgrep_result=$(docker exec "${TEST_CONTAINER_NAME}" pgrep -x openvpn 2>&1) || true
        if [[ -n "${pgrep_result}" ]] && [[ "${pgrep_result}" =~ ^[0-9]+$ ]]; then
            echo "# OpenVPN ready after ${count} seconds (PID: ${pgrep_result})" >&3 2>/dev/null || true
            return 0
        fi

        # Show progress every 10 seconds
        if [[ $((count % 10)) -eq 0 ]]; then
            echo "# Still waiting... ${count}s (pgrep output: '${pgrep_result}')" >&3 2>/dev/null || true
        fi
        sleep 1
        count=$((count + 1))
    done

    # Debug: show container logs on failure
    echo "# Timeout waiting for OpenVPN. Container logs:" >&3 2>/dev/null || true
    docker logs "${TEST_CONTAINER_NAME}" 2>&1 | tail -20 | while read -r line; do
        echo "# ${line}" >&3 2>/dev/null || true
    done

    return 1
}

# Execute command in test container
container_exec() {
    docker exec "${TEST_CONTAINER_NAME}" "$@"
}

# Get container logs
container_logs() {
    docker logs "${TEST_CONTAINER_NAME}" 2>&1
}

#===============================================================================
# PKI Verification
#===============================================================================

# Check if PKI is initialized in container
container_pki_initialized() {
    container_exec test -f /etc/openvpn/pki/ca.crt && \
    container_exec test -f /etc/openvpn/pki/issued/server.crt && \
    container_exec test -f /etc/openvpn/pki/private/server.key
}

# Get CA certificate from container
get_container_ca_cert() {
    container_exec cat /etc/openvpn/pki/ca.crt
}

# Verify server certificate
verify_container_server_cert() {
    local ca_cert
    ca_cert=$(container_exec cat /etc/openvpn/pki/ca.crt)
    local server_cert
    server_cert=$(container_exec cat /etc/openvpn/pki/issued/server.crt)

    echo "${ca_cert}" > /tmp/test_ca.crt
    echo "${server_cert}" > /tmp/test_server.crt

    openssl verify -CAfile /tmp/test_ca.crt /tmp/test_server.crt >/dev/null 2>&1
    local result=$?

    rm -f /tmp/test_ca.crt /tmp/test_server.crt
    return ${result}
}

#===============================================================================
# Client Certificate Testing
#===============================================================================

# Generate test client in container
generate_test_client() {
    local client_name="${1:-testclient}"
    container_exec generate-client "${client_name}"
}

# Check if client configs exist (all 6 configs)
client_configs_exist() {
    local client_name="${1}"
    container_exec test -f "/etc/openvpn/clients/${client_name}-udp-split.ovpn" && \
    container_exec test -f "/etc/openvpn/clients/${client_name}-udp-full.ovpn" && \
    container_exec test -f "/etc/openvpn/clients/${client_name}-tcp-split.ovpn" && \
    container_exec test -f "/etc/openvpn/clients/${client_name}-tcp-full.ovpn" && \
    container_exec test -f "/etc/openvpn/clients/${client_name}-https-split.ovpn" && \
    container_exec test -f "/etc/openvpn/clients/${client_name}-https-full.ovpn"
}

# Get client config content
# Usage: get_client_config <client_name> <protocol> <mode>
#   protocol: udp, tcp, https
#   mode: split, full
get_client_config() {
    local client_name="${1}"
    local protocol="${2:-udp}"
    local mode="${3:-split}"
    container_exec cat "/etc/openvpn/clients/${client_name}-${protocol}-${mode}.ovpn"
}

# Revoke test client
revoke_test_client() {
    local client_name="${1}"
    container_exec revoke-client "${client_name}"
}

#===============================================================================
# Configuration Testing
#===============================================================================

# Get server configuration
get_server_config() {
    container_exec cat /etc/openvpn/server/server.conf
}

# Check if OAuth2 is configured
oauth2_is_configured() {
    container_exec test -f /etc/openvpn-auth-oauth2/config.yaml
}

# Check if management socket exists
management_socket_exists() {
    container_exec test -S /run/openvpn/management.sock
}
