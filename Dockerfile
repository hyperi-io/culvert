#  Project:      culvert
#  File:         Dockerfile
#  Purpose:      Culvert server container image
#  Language:     Dockerfile
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Culvert Server
# OpenVPN 2.7+ with DCO and WireGuard in one image - each optionally
# tunnelled over HTTPS - plus OIDC SSO and external PKI
# Drop-in 'just works' docker or k8s scale deploy
#
# Build (production):
#   docker build \
#     --build-arg VERSION=1.0.0 \
#     -t ghcr.io/hyperi-io/culvert:1.0.0 .
#
# Build (development):
#   docker build -t culvert:dev .
#
# Features:
#   - OpenVPN 2.7.0+ from official repository (latest stable)
#   - Data Channel Offload (DCO) when the HOST provides the kernel module.
#     openvpn-dco-dkms is deliberately NOT installed here: DKMS would compile
#     against the container's absent kernel headers, and the module has to be
#     loaded on the host regardless - see vm-setup/setup-host.sh, which installs
#     it there. Leaving it out drops a compiler toolchain from the image without
#     costing the capability.
#   - CNSA 2.0 classical suite on the OpenVPN path (TLS 1.3, AES-256-GCM,
#     SHA-384, P-384). No ML-KEM or ML-DSA - the base image's OpenSSL has
#     neither. WireGuard's suite is fixed and outside CNSA.
#   - 4G/mobile network optimizations
#   - Generic OIDC SSO (Entra ID, Okta, Keycloak, Google, Auth0)
#   - Group-based access control
#   - Stateless design for horizontal scaling
#
# Supply Chain:
#   All third-party binaries are pulled directly from upstream GitHub releases.

# Base image pinned by digest so builds are reproducible. Override
# BASE_IMAGE to rebuild on a newer base. hadolint ignore=DL3006
ARG BASE_IMAGE="ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb"
ARG VERSION="dev"
ARG COMMIT=""

FROM ${BASE_IMAGE}

# Re-import ARGs into the image stage for use in LABELs
ARG VERSION
ARG COMMIT

LABEL maintainer="HyperI <opensource@hyperi.io>"
# The crypto claim is scoped deliberately. The suite is the CNSA 2.0
# CLASSICAL set and only on the OpenVPN path - WireGuard's suite is fixed
# outside CNSA, and there is no ML-KEM or ML-DSA, so an unqualified
# "CNSA 2.0 crypto" here would overstate it to anyone reading the label
# without the README's limits section in front of them.
LABEL description="Culvert - OpenVPN + WireGuard, optionally tunnelled over HTTPS, CNSA 2.0 classical suite on the OpenVPN path, OIDC SSO"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.source="https://github.com/hyperi-io/culvert"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL openvpn.version="2.7.0+"
LABEL openvpn.features="DCO,TLS1.3,AEAD,4G-optimized,OIDC-SSO"

ARG DEBIAN_FRONTEND=noninteractive
ARG OPENVPN_MIN_VERSION="2.7.0"
ARG OPENVPN_AUTH_OAUTH2_VERSION="1.28.3"
ARG OPENVPN_AUTH_OAUTH2_SHA256_AMD64="f762273dca8fe3449c51b8365cc0fa7dc5ad30d95720e7fde6d16bd17cd6d476"
ARG OPENVPN_AUTH_OAUTH2_SHA256_ARM64="f20b7f2ac713540ca996d7a8e522980b158c78f8a970ca9fa3f9c0c5e3b33f5d"

# openvpn from the project's signed apt repo. The downloaded keyring must carry
# EXACTLY ONE primary key and its fingerprint must be the pinned one, so neither
# a substituted key nor a second key smuggled in alongside the real one can
# reach /etc/apt/keyrings. Counting `pub` records rather than `fpr` records is
# deliberate: a key with signing subkeys emits an `fpr` line per subkey, all
# legitimately belonging to the same primary. Key 30EB F4E7 3CCE 63EE E124 DD27
# 8E6D A8B4 E158 C569 (Samuli Seppanen, expires 2030) - re-pin if it rotates.
#
# The installed openvpn is then checked against OPENVPN_MIN_VERSION. The apt
# repo serves one version per suite so it cannot be pinned, and the server
# config depends on 2.7 behaviour: persist-key is deprecated there and only 2.7
# clients reject an unknown pushed option, which is why block-outside-dns is not
# pushed. Silently building on 2.6 would change both.
# hadolint ignore=DL3008,DL3009
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
    && mkdir -p /etc/apt/keyrings \
    && curl --proto '=https' --tlsv1.2 -fsSL --max-time 30 \
         https://swupdate.openvpn.net/repos/repo-public.gpg -o /tmp/openvpn-repo.gpg \
    && gpg --show-keys --with-colons /tmp/openvpn-repo.gpg > /tmp/openvpn-repo.keys \
    && [ "$(grep -c '^pub:' /tmp/openvpn-repo.keys)" = "1" ] \
    && [ "$(awk -F: '/^pub:/{p=1;next} /^fpr:/&&p{print $10;exit}' /tmp/openvpn-repo.keys)" \
         = "30EBF4E73CCE63EEE124DD278E6DA8B4E158C569" ] \
    && rm /tmp/openvpn-repo.keys \
    && gpg --dearmor -o /etc/apt/keyrings/openvpn.gpg /tmp/openvpn-repo.gpg \
    && rm /tmp/openvpn-repo.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/openvpn.gpg] https://build.openvpn.net/debian/openvpn/stable $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/openvpn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        openvpn \
        easy-rsa \
        iptables \
        iproute2 \
        procps \
        openssl \
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
    && INSTALLED_OPENVPN="$(dpkg-query -W openvpn | cut -f2)" \
    && echo "openvpn ${INSTALLED_OPENVPN} (floor ${OPENVPN_MIN_VERSION})" \
    && dpkg --compare-versions "${INSTALLED_OPENVPN}" ge "${OPENVPN_MIN_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# openvpn-auth-oauth2 from a pinned release .deb, checksum-checked before
# dpkg. Its apt repo serves releases/latest (Suites ./) and cannot be pinned
# to a version, which would make the image non-reproducible - hence the
# artefact fetch. Version + SHA are bumped by
# .github/workflows/dependency-check.yml.
# Source: https://github.com/jkroepke/openvpn-auth-oauth2
RUN ARCH=$(dpkg --print-architecture) \
    && case "${ARCH}" in \
         amd64) OAUTH2_SHA256="${OPENVPN_AUTH_OAUTH2_SHA256_AMD64}" ;; \
         arm64) OAUTH2_SHA256="${OPENVPN_AUTH_OAUTH2_SHA256_ARM64}" ;; \
         *) echo "Unsupported architecture: ${ARCH}" >&2 && exit 1 ;; \
       esac \
    && DEB_FILE="openvpn-auth-oauth2_${OPENVPN_AUTH_OAUTH2_VERSION}_linux_${ARCH}.deb" \
    && curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 \
         "https://github.com/jkroepke/openvpn-auth-oauth2/releases/download/v${OPENVPN_AUTH_OAUTH2_VERSION}/${DEB_FILE}" \
         -o /tmp/openvpn-auth-oauth2.deb \
    && echo "${OAUTH2_SHA256}  /tmp/openvpn-auth-oauth2.deb" | sha256sum -c - \
    && dpkg -i /tmp/openvpn-auth-oauth2.deb \
    && rm /tmp/openvpn-auth-oauth2.deb \
    && openvpn-auth-oauth2 --version

# Python dependencies from requirements-docker.txt, a hash-pinned lockfile
# exported from uv.lock. --require-hashes means every transitive dep must
# match its recorded SHA256, so a drifted or compromised PyPI release fails
# the build rather than shipping. The granular secrets extras (file backend
# is core, openbao=secrets-vault, aws=secrets-aws) plus otel are baked into
# the lockfile; regenerate on any uv.lock change with:
#   uv export --frozen --no-dev --no-emit-project --extra otel \
#     --format requirements-txt -o requirements-docker.txt
COPY requirements-docker.txt /tmp/requirements-docker.txt
RUN pip3 install --no-cache-dir --break-system-packages \
        --require-hashes -r /tmp/requirements-docker.txt \
    && rm /tmp/requirements-docker.txt

# scalo config cascade reads CULVERT_* env vars
ENV ENV_PREFIX=CULVERT

# wstunnel from a pinned release tarball, checksum-checked before extract.
# There is no apt repo, and the upstream container image's binary links
# against a glibc newer than the base image's, so the tarball is the only
# option that runs here. BSD-3-Clause Rust binary.
ARG WSTUNNEL_VERSION="10.6.2"
ARG WSTUNNEL_SHA256_AMD64="db6064cca0515b67f8652e201cff8e27553b8cbb7216b2e19241311e34868e6e"
ARG WSTUNNEL_SHA256_ARM64="26bb36b856948255bec7cd71a39df5f8912acdd7a47a9ccd4044a9b80ced108d"
RUN ARCH=$(dpkg --print-architecture) \
    && case "${ARCH}" in \
         amd64) WSTUNNEL_SHA256="${WSTUNNEL_SHA256_AMD64}" ;; \
         arm64) WSTUNNEL_SHA256="${WSTUNNEL_SHA256_ARM64}" ;; \
         *) echo "Unsupported architecture: ${ARCH}" >&2 && exit 1 ;; \
       esac \
    && TARBALL="wstunnel_${WSTUNNEL_VERSION}_linux_${ARCH}.tar.gz" \
    && curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 \
         "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/${TARBALL}" \
         -o /tmp/wstunnel.tar.gz \
    && echo "${WSTUNNEL_SHA256}  /tmp/wstunnel.tar.gz" | sha256sum -c - \
    && tar xz -f /tmp/wstunnel.tar.gz -C /usr/local/bin/ wstunnel \
    && rm /tmp/wstunnel.tar.gz \
    && chmod +x /usr/local/bin/wstunnel

WORKDIR /etc/vpn

# Create directory structure
RUN mkdir -p /etc/vpn/pki /etc/vpn/server/ccd /etc/vpn/clients \
    /etc/vpn/scripts /etc/vpn/docs /var/log/vpn

# The canonical paths are /etc/vpn and /var/log/vpn, and nothing aliases them.
#
# There were compatibility symlinks to the legacy openvpn directories here. They
# never worked: the openvpn package already owns both as real directories, so
# `ln -s` created a link INSIDE each one rather than the alias it looks like.
# Anything mounted at the legacy PKI path therefore landed somewhere the server
# never reads, which silently defeated PKI persistence - a fresh CA on every
# recreate. Removed rather than forced over package-owned directories: one set
# of paths, and a mount at the wrong one now fails visibly instead of appearing
# to work.

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

# Shipped deployment profiles (opt-in via CULVERT_PROFILE)
COPY profiles/ /etc/vpn/profiles/

# OAuth2 branding assets
COPY oauth2-assets/ /etc/openvpn-auth-oauth2/assets/

# Client documentation
COPY docs/vpn-client-setup.md /etc/vpn/docs/vpn-client-setup.md

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
# TCP 443  - OpenVPN inside a TLS tunnel (stunnel), for networks that only
#            pass HTTPS
# UDP 51820 - WireGuard
# TCP 4443 - WireGuard inside a WebSocket/TLS tunnel (wstunnel), same purpose
# TCP 9000-9002 - OAuth2 callback servers
# TCP 9090 - Observability (health probes + Prometheus /metrics)
EXPOSE 1194/udp 1194/tcp 443/tcp 51820/udp 4443/tcp 9000/tcp 9001/tcp 9002/tcp 9090/tcp

# Protocol-aware health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/entrypoint.py", "healthcheck"]

ENTRYPOINT ["/entrypoint.py"]
CMD ["server"]
