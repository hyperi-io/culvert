#!/usr/bin/env bash
#  Project:      hyperi-vpn
#  File:         e2e_helper.bash
#  Purpose:      VPN connection testing helpers
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Default E2E configuration
E2E_VPN_HOST="${E2E_VPN_HOST:-your-vpn.example.com}"
E2E_VPN_UDP_PORT="${E2E_VPN_UDP_PORT:-1194}"
E2E_VPN_TCP_PORT="${E2E_VPN_TCP_PORT:-443}"
E2E_SSH_USER="${E2E_SSH_USER:-root}"
E2E_SSH_KEY="${E2E_SSH_KEY:-}"
E2E_VPN_NETWORK="${E2E_VPN_NETWORK:-10.8.0.0/24}"
E2E_VPN_GATEWAY="${E2E_VPN_GATEWAY:-10.8.0.1}"

# Test client storage
E2E_TEST_CLIENT_DIR="${E2E_TEST_CLIENT_DIR:-/tmp/openvpn-e2e-test}"

#===============================================================================
# Configuration Loading
#===============================================================================

# Load E2E configuration from file
load_e2e_config() {
    local config_file="${TEST_ROOT}/e2e/config.env"

    if [[ -f "${config_file}" ]]; then
        # shellcheck source=/dev/null
        source "${config_file}"
    fi

    # Validate required configuration
    if [[ -z "${E2E_VPN_HOST}" ]]; then
        echo "E2E_VPN_HOST not configured" >&2
        return 1
    fi

    # Create test directory
    mkdir -p "${E2E_TEST_CLIENT_DIR}"
}

#===============================================================================
# SSH Helpers (for managing test VM)
#===============================================================================

# SSH command wrapper
ssh_to_vpn() {
    local ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

    if [[ -n "${E2E_SSH_KEY}" ]]; then
        ssh_opts+=(-i "${E2E_SSH_KEY}")
    fi

    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${E2E_SSH_USER}@${E2E_VPN_HOST}" "$@"
}

# SCP command wrapper
scp_from_vpn() {
    local remote_path="${1}"
    local local_path="${2}"
    local ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

    if [[ -n "${E2E_SSH_KEY}" ]]; then
        ssh_opts+=(-i "${E2E_SSH_KEY}")
    fi

    scp "${ssh_opts[@]}" "${E2E_SSH_USER}@${E2E_VPN_HOST}:${remote_path}" "${local_path}"
}

# Check if test VM is accessible
ensure_test_vm_ready() {
    local timeout="${1:-30}"
    local count=0

    echo "Checking connectivity to ${E2E_VPN_HOST}..."

    while [[ ${count} -lt ${timeout} ]]; do
        if ssh_to_vpn "echo ok" >/dev/null 2>&1; then
            echo "Test VM is accessible"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done

    echo "Cannot reach test VM at ${E2E_VPN_HOST}" >&2
    return 1
}

# Check if VPN container is running on test VM
vpn_container_running() {
    ssh_to_vpn "docker ps --filter name=hyperi-vpn --format '{{.Status}}'" | grep -q "Up"
}

# Restart VPN container on test VM
restart_vpn_container() {
    ssh_to_vpn "cd /opt/openvpn && docker compose restart"
    sleep 5  # Wait for container to stabilize
}

#===============================================================================
# Client Certificate Management
#===============================================================================

# Generate test client on VPN server
generate_e2e_test_client() {
    local client_name="${1:-e2e-test-$(date +%s)}"

    echo "Generating test client: ${client_name}"
    ssh_to_vpn "docker exec hyperi-vpn generate-client ${client_name}"

    # Download configs
    scp_from_vpn "/var/lib/docker/volumes/openvpn-clients/_data/${client_name}-split.ovpn" \
        "${E2E_TEST_CLIENT_DIR}/${client_name}-split.ovpn"
    scp_from_vpn "/var/lib/docker/volumes/openvpn-clients/_data/${client_name}-full.ovpn" \
        "${E2E_TEST_CLIENT_DIR}/${client_name}-full.ovpn"

    echo "${client_name}"
}

# Revoke test client on VPN server
revoke_e2e_test_client() {
    local client_name="${1}"

    echo "Revoking test client: ${client_name}"
    ssh_to_vpn "docker exec hyperi-vpn revoke-client ${client_name}"

    # Remove local configs
    rm -f "${E2E_TEST_CLIENT_DIR}/${client_name}-"*.ovpn
}

# List all test clients
list_e2e_test_clients() {
    ssh_to_vpn "docker exec hyperi-vpn ls /etc/openvpn/clients/" 2>/dev/null | \
        grep -E '^e2e-test-.*\.ovpn$' | sed 's/-\(split\|full\)\.ovpn$//' | sort -u
}

# Clean up all test clients
cleanup_e2e_test_clients() {
    local clients
    clients=$(list_e2e_test_clients)

    for client in ${clients}; do
        revoke_e2e_test_client "${client}" || true
    done

    rm -rf "${E2E_TEST_CLIENT_DIR}"
}

#===============================================================================
# VPN Client Detection and Setup
#===============================================================================

# Check which OpenVPN client is available
# Preference: openvpn3 (modern) > openvpn (legacy)
detect_openvpn_client() {
    if command -v openvpn3 >/dev/null 2>&1; then
        echo "openvpn3"
    elif command -v openvpn >/dev/null 2>&1; then
        echo "openvpn"
    else
        echo ""
    fi
}

# Install openvpn3 client from official repository
# This is the recommended modern client with better daemon management
install_openvpn3_client() {
    echo "Installing OpenVPN3 client from official repository..."

    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y apt-transport-https gnupg

        # Add OpenVPN repository
        local distro_codename
        distro_codename=$(lsb_release -cs)

        curl -fsSL https://swupdate.openvpn.net/repos/openvpn-repo-pkg-key.pub | \
            sudo gpg --dearmor -o /etc/apt/keyrings/openvpn-repo.gpg

        echo "deb [signed-by=/etc/apt/keyrings/openvpn-repo.gpg] https://swupdate.openvpn.net/community/openvpn3/repos/${distro_codename} ${distro_codename} main" | \
            sudo tee /etc/apt/sources.list.d/openvpn3.list

        sudo apt-get update
        sudo apt-get install -y openvpn3

    elif [[ -f /etc/redhat-release ]]; then
        # RHEL/CentOS/Fedora
        local releasever
        releasever=$(rpm -E %rhel)

        sudo yum install -y "https://swupdate.openvpn.net/community/openvpn3/repos/openvpn3-rhel${releasever}-repo.rpm" || \
        sudo dnf install -y "https://swupdate.openvpn.net/community/openvpn3/repos/openvpn3-rhel${releasever}-repo.rpm"

        sudo yum install -y openvpn3-client || sudo dnf install -y openvpn3-client

    else
        echo "Unsupported distribution. Please install openvpn3 manually." >&2
        echo "See: https://openvpn.net/cloud-docs/openvpn-3-client-for-linux/" >&2
        return 1
    fi

    echo "OpenVPN3 client installed successfully"
}

#===============================================================================
# VPN Connection (OpenVPN3 preferred, legacy fallback)
#===============================================================================

# Connect to VPN using client config
connect_vpn() {
    local config_file="${1}"
    local timeout="${2:-30}"

    if [[ ! -f "${config_file}" ]]; then
        echo "Config file not found: ${config_file}" >&2
        return 1
    fi

    local client
    client=$(detect_openvpn_client)

    if [[ -z "${client}" ]]; then
        echo "No OpenVPN client found. Install openvpn3 with: install_openvpn3_client" >&2
        return 1
    fi

    echo "Using OpenVPN client: ${client}"

    if [[ "${client}" == "openvpn3" ]]; then
        # Modern OpenVPN3 client
        connect_vpn_openvpn3 "${config_file}" "${timeout}"
    else
        # Legacy OpenVPN client (requires sudo)
        connect_vpn_legacy "${config_file}" "${timeout}"
    fi
}

# Connect using OpenVPN3 client (recommended)
connect_vpn_openvpn3() {
    local config_file="${1}"
    local timeout="${2:-30}"

    # Import config if not already imported
    local config_name
    config_name=$(basename "${config_file}" .ovpn)

    # Remove existing config with same name
    openvpn3 config-remove --config "${config_name}" 2>/dev/null || true

    # Import new config
    echo "Importing OpenVPN3 config: ${config_name}"
    openvpn3 config-import --config "${config_file}" --name "${config_name}"

    # Start session
    echo "Starting OpenVPN3 session..."
    openvpn3 session-start --config "${config_name}" &

    # Wait for connection
    local count=0
    while [[ ${count} -lt ${timeout} ]]; do
        if ip addr show tun0 >/dev/null 2>&1; then
            echo "VPN connected (OpenVPN3)"
            return 0
        fi

        # Check session status
        if openvpn3 sessions-list 2>/dev/null | grep -q "Connection.*established"; then
            # Give it a moment for tun interface
            sleep 2
            if ip addr show tun0 >/dev/null 2>&1; then
                echo "VPN connected (OpenVPN3)"
                return 0
            fi
        fi

        sleep 1
        count=$((count + 1))
    done

    echo "VPN connection timeout (OpenVPN3)" >&2
    openvpn3 sessions-list 2>&1 || true
    return 1
}

# Connect using legacy OpenVPN client (requires sudo)
connect_vpn_legacy() {
    local config_file="${1}"
    local timeout="${2:-30}"

    # Start OpenVPN in background (requires root)
    sudo openvpn --config "${config_file}" --daemon --log /tmp/openvpn-test.log \
        --writepid /tmp/openvpn-test.pid

    # Wait for connection
    local count=0
    while [[ ${count} -lt ${timeout} ]]; do
        if ip addr show tun0 >/dev/null 2>&1; then
            echo "VPN connected (legacy client)"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done

    echo "VPN connection timeout (legacy)" >&2
    cat /tmp/openvpn-test.log >&2
    return 1
}

# Disconnect from VPN
disconnect_vpn() {
    local client
    client=$(detect_openvpn_client)

    if [[ "${client}" == "openvpn3" ]]; then
        # Disconnect all OpenVPN3 sessions
        for session_path in $(openvpn3 sessions-list 2>/dev/null | grep "^/net/openvpn" | awk '{print $1}'); do
            openvpn3 session-manage --disconnect --session-path "${session_path}" 2>/dev/null || true
        done

        # Remove imported configs
        for config in $(openvpn3 configs-list 2>/dev/null | grep "^/net/openvpn" | awk '{print $1}'); do
            openvpn3 config-remove --config-path "${config}" 2>/dev/null || true
        done
    fi

    # Also handle legacy client
    if [[ -f /tmp/openvpn-test.pid ]]; then
        sudo kill "$(cat /tmp/openvpn-test.pid)" 2>/dev/null || true
        rm -f /tmp/openvpn-test.pid
    fi

    # Kill any stray openvpn processes from tests
    sudo pkill -f "openvpn --config.*e2e-test" 2>/dev/null || true

    # Wait for interface to go down
    local count=0
    while ip addr show tun0 >/dev/null 2>&1 && [[ ${count} -lt 10 ]]; do
        sleep 1
        count=$((count + 1))
    done
}

# Check if VPN is connected
vpn_is_connected() {
    ip addr show tun0 >/dev/null 2>&1 && \
    ip route | grep -q "${E2E_VPN_NETWORK}"
}

# Get VPN client IP
get_vpn_client_ip() {
    ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1
}

#===============================================================================
# Connectivity Tests
#===============================================================================

# Test ping to VPN gateway
ping_vpn_gateway() {
    ping -c 3 -W 2 "${E2E_VPN_GATEWAY}" >/dev/null 2>&1
}

# Test DNS resolution through VPN
test_vpn_dns() {
    # This tests if DNS is working through the VPN
    local test_domain="${1:-google.com}"
    nslookup "${test_domain}" >/dev/null 2>&1
}

# Test full tunnel routing (all traffic through VPN)
test_full_tunnel() {
    # Check if default route goes through tun0
    ip route | grep "^default" | grep -q "tun0"
}

# Test split tunnel routing (only VPN network through VPN)
test_split_tunnel() {
    # Check that default route does NOT go through tun0
    ! ip route | grep "^default" | grep -q "tun0" && \
    # But VPN network does
    ip route | grep "${E2E_VPN_NETWORK}" | grep -q "tun0"
}

# Get public IP (to verify full tunnel)
get_public_ip() {
    curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
    curl -s --max-time 5 https://ifconfig.me 2>/dev/null
}

#===============================================================================
# Protocol Tests
#===============================================================================

# Test UDP connectivity
test_udp_connectivity() {
    nc -u -z -w 3 "${E2E_VPN_HOST}" "${E2E_VPN_UDP_PORT}" 2>/dev/null
}

# Test TCP connectivity
test_tcp_connectivity() {
    nc -z -w 3 "${E2E_VPN_HOST}" "${E2E_VPN_TCP_PORT}" 2>/dev/null
}

# Test OAuth2 endpoint
test_oauth2_endpoint() {
    local oauth2_port="${E2E_OAUTH2_PORT:-9000}"
    curl -s --max-time 5 "http://${E2E_VPN_HOST}:${oauth2_port}/" >/dev/null 2>&1
}

#===============================================================================
# Cleanup
#===============================================================================

# Full E2E cleanup
e2e_cleanup() {
    disconnect_vpn
    cleanup_e2e_test_clients
    rm -f /tmp/openvpn-test.log
}
