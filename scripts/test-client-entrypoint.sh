#!/usr/bin/env bash
#  Project:      hyperi-vpn
#  File:         test-client-entrypoint.sh
#  Purpose:      Test client container entrypoint
#  Language:     Bash
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Usage: docker run ... dfe-vpn-client /path/to/config.ovpn
#        docker run ... dfe-vpn-client shell

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

test_connectivity() {
    log_info "Testing VPN connectivity..."

    # Wait for tun interface
    local timeout=30
    local count=0
    while ! ip addr show tun0 >/dev/null 2>&1; do
        sleep 1
        ((count++))
        if [[ ${count} -ge ${timeout} ]]; then
            log_error "Timeout waiting for tun0 interface"
            return 1
        fi
    done

    log_info "TUN interface is up"
    ip addr show tun0

    # Test DNS
    log_info "Testing DNS resolution..."
    if nslookup google.com >/dev/null 2>&1; then
        log_info "DNS resolution: OK"
    else
        log_warn "DNS resolution: FAILED"
    fi

    # Test external connectivity
    log_info "Testing external connectivity..."
    if curl -s --max-time 5 -o /dev/null https://ifconfig.me; then
        local public_ip
        public_ip=$(curl -s --max-time 5 https://ifconfig.me)
        log_info "External connectivity: OK (Public IP: ${public_ip})"
    else
        log_warn "External connectivity: FAILED or no internet"
    fi

    log_info "VPN test complete"
}

case "${1:-}" in
    shell|bash)
        log_info "Starting shell..."
        exec /bin/bash
        ;;
    test)
        test_connectivity
        ;;
    *.ovpn)
        if [[ ! -f "${1}" ]]; then
            log_error "Config file not found: ${1}"
            exit 1
        fi
        log_info "Starting OpenVPN client with: ${1}"

        # Start OpenVPN in background
        openvpn --config "${1}" &
        OPENVPN_PID=$!

        # Wait for connection and test
        sleep 5
        test_connectivity

        # Keep running
        log_info "VPN connected. Press Ctrl+C to disconnect."
        wait "${OPENVPN_PID}"
        ;;
    "")
        log_info "OpenVPN Test Client"
        echo ""
        echo "Usage:"
        echo "  ${0} /path/to/config.ovpn   - Connect using config file"
        echo "  ${0} shell                   - Start interactive shell"
        echo "  ${0} test                    - Test existing VPN connection"
        echo ""
        echo "Available configs in /etc/vpn/clients/:"
        ls -1 /etc/vpn/clients/*.ovpn 2>/dev/null || echo "  (none)"
        ;;
    *)
        log_error "Unknown command: ${1}"
        exit 1
        ;;
esac
