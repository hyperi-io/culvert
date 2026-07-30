#!/usr/bin/env bash
#  Project:      culvert
#  File:         docker_helper.bash
#  Purpose:      Docker container lifecycle helpers for tests
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Test container configuration.
#
# Names carry the project and tier so a stray is identifiable at a glance, and
# the test file it came from so a stray points at what left it. One container
# per test FILE, shared by every test in that file: BATS_TEST_FILENAME is the
# same across setup_file, the tests and teardown_file.
if [[ -n "${BATS_TEST_FILENAME:-}" ]]; then
    _test_file_base=$(basename "${BATS_TEST_FILENAME}" .bats)
    TEST_CONTAINER_NAME="culvert-test-integration-${_test_file_base}"
else
    # Outside BATS - a fixed name for driving the helpers by hand.
    TEST_CONTAINER_NAME="culvert-test-integration-manual"
fi
TEST_IMAGE_NAME="culvert:test"
TEST_NETWORK="culvert-test-integration-net"

#===============================================================================
# Container Management
#===============================================================================

# Build test container image
build_test_container() {
    docker build -t "${TEST_IMAGE_NAME}" "${PROJECT_ROOT}" >/dev/null 2>&1
}

# Start the test container.
#
# Accepts `-e KEY=VALUE` (repeatable), `--env-file PATH`, or a bare path to an
# env file. The `-e` form is what the callers use: the original signature took
# only a bare env-file path, so `start_test_container -e "CULVERT_PROTOCOL=..."`
# passed "-e" as the filename, found no such file, and started the container
# with the variable silently absent - every WireGuard test then asserted against
# a server running the default OpenVPN-only configuration.
start_test_container() {
    local extra_args=()

    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -e|--env)
                extra_args+=(--env "${2}")
                shift 2
                ;;
            --env-file)
                extra_args+=(--env-file "${2}")
                shift 2
                ;;
            *)
                if [[ -f "${1}" ]]; then
                    extra_args+=(--env-file "${1}")
                else
                    echo "start_test_container: ignoring unknown argument '${1}'" >&2
                    return 2
                fi
                shift
                ;;
        esac
    done

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

# Wait for the container to report itself ready.
#
# Polls /readyz, the server's own readiness contract, rather than looking for an
# openvpn process. In CULVERT_PROTOCOL=wireguard mode there is no openvpn process
# at all, so the process check could never succeed and every WireGuard test timed
# out here regardless of whether the server was fine.
wait_for_container_ready() {
    local timeout="${1:-60}"
    local count=0

    echo "# Waiting for container: ${TEST_CONTAINER_NAME}" >&3 2>/dev/null || true

    while [[ ${count} -lt ${timeout} ]]; do
        if ! docker inspect "${TEST_CONTAINER_NAME}" >/dev/null 2>&1; then
            echo "# Container ${TEST_CONTAINER_NAME} not found (attempt ${count})" >&3 2>/dev/null || true
            sleep 1
            count=$((count + 1))
            continue
        fi

        local state
        state=$(docker inspect --format='{{.State.Status}}' "${TEST_CONTAINER_NAME}" 2>/dev/null)
        if [[ "${state}" != "running" ]]; then
            echo "# Container state: ${state} (attempt ${count})" >&3 2>/dev/null || true
            sleep 1
            count=$((count + 1))
            continue
        fi

        if docker exec "${TEST_CONTAINER_NAME}" \
            curl -sf http://localhost:9090/readyz >/dev/null 2>&1; then
            echo "# Ready after ${count} seconds" >&3 2>/dev/null || true
            return 0
        fi

        if [[ $((count % 10)) -eq 0 ]]; then
            echo "# Still waiting for /readyz... ${count}s" >&3 2>/dev/null || true
        fi
        sleep 1
        count=$((count + 1))
    done

    # Debug: show container logs on failure
    echo "# Timeout waiting for /readyz. Container logs:" >&3 2>/dev/null || true
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
    container_exec test -f /etc/vpn/pki/ca.crt && \
    container_exec test -f /etc/vpn/pki/issued/server.crt && \
    container_exec test -f /etc/vpn/pki/private/server.key
}

# Get CA certificate from container
get_container_ca_cert() {
    container_exec cat /etc/vpn/pki/ca.crt
}

# Verify server certificate
verify_container_server_cert() {
    local ca_cert
    ca_cert=$(container_exec cat /etc/vpn/pki/ca.crt)
    local server_cert
    server_cert=$(container_exec cat /etc/vpn/pki/issued/server.crt)

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
    container_exec test -f "/etc/vpn/clients/${client_name}-udp-split.ovpn" && \
    container_exec test -f "/etc/vpn/clients/${client_name}-udp-full.ovpn" && \
    container_exec test -f "/etc/vpn/clients/${client_name}-tcp-split.ovpn" && \
    container_exec test -f "/etc/vpn/clients/${client_name}-tcp-full.ovpn" && \
    container_exec test -f "/etc/vpn/clients/${client_name}-https-split.ovpn" && \
    container_exec test -f "/etc/vpn/clients/${client_name}-https-full.ovpn"
}

# Get client config content
# Usage: get_client_config <client_name> <protocol> <mode>
#   protocol: udp, tcp, https
#   mode: split, full
get_client_config() {
    local client_name="${1}"
    local protocol="${2:-udp}"
    local mode="${3:-split}"
    container_exec cat "/etc/vpn/clients/${client_name}-${protocol}-${mode}.ovpn"
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
    container_exec cat /etc/vpn/server/server.conf
}

# Check if OAuth2 is configured.
#
# One config per listener - config-udp.yaml, config-tcp.yaml, config-https.yaml -
# so there is no single config.yaml to test for. Match any of them.
oauth2_is_configured() {
    local listing
    listing=$(container_exec sh -c 'ls /etc/openvpn-auth-oauth2/config-*.yaml 2>/dev/null') || return 1
    [[ -n "${listing}" ]]
}

# Check if the management socket exists.
#
# One socket per listener under /run/vpn, named for the listener - the UDP one
# is always present when OpenVPN is running.
management_socket_exists() {
    container_exec test -S /run/vpn/management-udp.sock
}
