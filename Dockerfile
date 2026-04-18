#  Project:      hyperi-vpn
#  File:         Dockerfile
#  Purpose:      HyperI VPN server container image
#  Language:     Dockerfile
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# HyperI VPN Server
# Enterprise-grade OpenVPN 2.6.15+ with DCO, CNSA 2.0 security, and OIDC SSO
#
# Build (production):
#   docker build \
#     --build-arg VERSION=1.0.0 \
#     -t ghcr.io/hyperi-io/hyperi-vpn:1.0.0 .
#
# Build (development):
#   docker build -t hyperi-vpn:dev .
#
# Features:
#   - OpenVPN 2.7.0+ from official repository (latest stable)
#   - Data Channel Offload (DCO) for kernel-space encryption
#   - CNSA 2.0 aligned cryptography (TLS 1.3, AES-256-GCM, SHA-384)
#   - 4G/mobile network optimizations
#   - Generic OIDC SSO (Entra ID, Okta, Keycloak, Google, Auth0)
#   - Group-based access control
#   - Stateless design for horizontal scaling
#   - Auto-patching with unattended-upgrades
#
# Supply Chain:
#   All third-party binaries are pulled directly from upstream GitHub releases.

# hadolint ignore=DL3006
ARG BASE_IMAGE="ubuntu:24.04"
ARG VERSION="dev"
ARG COMMIT=""

FROM ${BASE_IMAGE}

# Re-import ARGs into the image stage for use in LABELs
ARG VERSION
ARG COMMIT

LABEL maintainer="HyperI <opensource@hyperi.io>"
LABEL description="HyperI VPN — OpenVPN + WireGuard with DPI bypass, CNSA 2.0, and OIDC SSO"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.source="https://github.com/hyperi-io/hyperi-vpn"
LABEL org.opencontainers.image.licenses="FSL-1.1-ALv2"
LABEL openvpn.version="2.7.0+"
LABEL openvpn.features="DCO,TLS1.3,AEAD,4G-optimized,OIDC-SSO"

ARG DEBIAN_FRONTEND=noninteractive
ARG OPENVPN_MIN_VERSION="2.7.0"
ARG OPENVPN_AUTH_OAUTH2_VERSION="1.26.0"

# hadolint ignore=DL3008,DL3009
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg \
       | gpg --dearmor -o /etc/apt/keyrings/openvpn.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/openvpn.gpg] https://build.openvpn.net/debian/openvpn/stable $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/openvpn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        openvpn \
        openvpn-dco-dkms \
        easy-rsa \
        iptables \
        iproute2 \
        procps \
        openssl \
        unattended-upgrades \
        apt-listchanges \
        kmod \
        logrotate \
        python3 \
        python3-pip \
        wireguard-tools \
        stunnel4 \
        iputils-ping \
        net-tools \
        tcpdump \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# openvpn-auth-oauth2 (OIDC SSO)
# Source: https://github.com/jkroepke/openvpn-auth-oauth2
RUN ARCH=$(dpkg --print-architecture) \
    && DEB_FILE="openvpn-auth-oauth2_${OPENVPN_AUTH_OAUTH2_VERSION}_linux_${ARCH}.deb" \
    && curl -fsSL "https://github.com/jkroepke/openvpn-auth-oauth2/releases/download/v${OPENVPN_AUTH_OAUTH2_VERSION}/${DEB_FILE}" \
         -o /tmp/openvpn-auth-oauth2.deb \
    && dpkg -i /tmp/openvpn-auth-oauth2.deb \
    && rm /tmp/openvpn-auth-oauth2.deb \
    && openvpn-auth-oauth2 --version

# Unattended upgrades (auto-patching)
RUN echo 'Unattended-Upgrade::Allowed-Origins {\n\
    "${distro_id}:${distro_codename}";\n\
    "${distro_id}:${distro_codename}-security";\n\
    "${distro_id}ESMApps:${distro_codename}-apps-security";\n\
    "${distro_id}ESM:${distro_codename}-infra-security";\n\
    "origin=build.openvpn.net";\n\
};\n\
Unattended-Upgrade::AutoFixInterruptedDpkg "true";\n\
Unattended-Upgrade::MinimalSteps "true";\n\
Unattended-Upgrade::Remove-Unused-Dependencies "true";\n\
Unattended-Upgrade::Automatic-Reboot "false";' > /etc/apt/apt.conf.d/50unattended-upgrades

# Python dependencies (hyperi-pylib for logging, config, metrics, secrets)
# hadolint ignore=DL3013
RUN pip3 install --no-cache-dir --break-system-packages \
    "hyperi-pylib[metrics,secrets]>=2.25,<3"

# Optional: OTel support (adds ~4MB)
ARG OTEL_SUPPORT=true
RUN if [ "$OTEL_SUPPORT" = "true" ]; then \
        pip3 install --no-cache-dir --break-system-packages \
            "hyperi-pylib[opentelemetry]>=2.25,<3"; \
    fi

# hyperi-pylib config cascade reads HYPERI_VPN_* env vars
ENV HYPERI_LIB_ENV_PREFIX=HYPERI_VPN

# wstunnel (DPI bypass for WireGuard — BSD-3-Clause, Rust binary)
# Web search for current version at build time
ARG WSTUNNEL_VERSION="10.5.2"
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL \
         "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/wstunnel_${WSTUNNEL_VERSION}_linux_${ARCH}.tar.gz" \
         | tar xz -C /usr/local/bin/ wstunnel \
    && chmod +x /usr/local/bin/wstunnel

WORKDIR /etc/vpn

# Create directory structure
RUN mkdir -p /etc/vpn/pki /etc/vpn/server/ccd /etc/vpn/clients \
    /etc/vpn/scripts /etc/vpn/docs /var/log/vpn

# Backwards compatibility symlinks (existing volume mounts to /etc/openvpn still work)
RUN ln -s /etc/vpn /etc/openvpn \
    && ln -s /var/log/vpn /var/log/openvpn

# Configuration templates (processed by envsubst at runtime)
COPY config/server.conf.template /etc/vpn/server/server.conf.template
COPY config/server-https.conf.template /etc/vpn/server/server-https.conf.template
COPY config/server-tcp.conf.template /etc/vpn/server/server-tcp.conf.template
COPY config/stunnel-server.conf.template /etc/vpn/server/stunnel-server.conf.template

# Entrypoint and management scripts
COPY scripts/entrypoint.py /entrypoint.py
COPY scripts/generate-client.py /usr/local/bin/generate-client
COPY scripts/revoke-client.py /usr/local/bin/revoke-client
COPY scripts/update-crl.py /usr/local/bin/update-crl

# Shared library modules (config, process, network, pki, openvpn, wireguard, etc.)
COPY scripts/lib/ /etc/vpn/scripts/lib/

# Shipped deployment profiles (opt-in via HYPERI_VPN_PROFILE)
COPY profiles/ /etc/vpn/profiles/

# OAuth2 branding assets
COPY oauth2-assets/ /etc/openvpn-auth-oauth2/assets/

# Client documentation
COPY docs/VPN-CLIENT-SETUP.md /etc/vpn/docs/VPN-CLIENT-SETUP.md

RUN chmod +x /entrypoint.py /usr/local/bin/generate-client \
    /usr/local/bin/revoke-client /usr/local/bin/update-crl

# PYTHONPATH for lib/ module imports (entrypoint is at / but lib/ is under scripts/)
ENV PYTHONPATH="/etc/vpn/scripts"

# Bake version info for runtime inspection
ARG VERSION
ARG COMMIT
RUN echo "${VERSION}" > /etc/vpn/VERSION \
    && echo "${COMMIT}" > /etc/vpn/COMMIT

# Volumes for persistent data
VOLUME ["/etc/vpn/pki", "/etc/vpn/server/ccd", "/etc/vpn/clients", "/var/log/vpn"]

# UDP 1194 - OpenVPN (best performance with DCO)
# TCP 1194 - OpenVPN TCP fallback
# TCP 443  - OpenVPN HTTPS tunneling (stunnel DPI bypass)
# UDP 51820 - WireGuard
# TCP 4443 - WireGuard DPI bypass (wstunnel)
# TCP 9000-9002 - OAuth2 callback servers
# TCP 8080 - Health endpoints
# TCP 9176 - Prometheus metrics
EXPOSE 1194/udp 1194/tcp 443/tcp 51820/udp 4443/tcp 9000/tcp 9001/tcp 9002/tcp 8080/tcp 9176/tcp

# Protocol-aware health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/entrypoint.py", "healthcheck"]

ENTRYPOINT ["/entrypoint.py"]
CMD ["server"]
