#!/usr/bin/env bash
set -euo pipefail

# Generate self-signed TLS cert for stunnel (HTTPS DPI bypass)
mkdir -p /etc/vpn/oauth2-tls
if [ ! -f /etc/vpn/oauth2-tls/hyperi-wildcard-fullchain.pem ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /etc/vpn/oauth2-tls/hyperi-wildcard.key \
        -out /etc/vpn/oauth2-tls/hyperi-wildcard-fullchain.pem \
        -days 1 -nodes -subj '/CN=*.hyperi.io' 2>/dev/null
fi

# The entrypoint's setup_network only MASQUERADEs VPN subnets on the default
# route interface. In a multi-homed compose setup the target may be on a
# different interface. Add catch-all MASQUERADE for all VPN subnets so traffic
# routes correctly regardless of which interface leads to the target.
for subnet in 192.168.100.0/24 192.168.101.0/24 192.168.102.0/24 192.168.200.0/24; do
    iptables -t nat -A POSTROUTING -s "${subnet}" -j MASQUERADE 2>/dev/null || true
done

# Hand off to the real entrypoint
exec /entrypoint.py "$@"
