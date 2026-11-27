#  Project:      culvert
#  File:         Dockerfile
#  Purpose:      Culvert server container image
#  Language:     Dockerfile
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Culvert server image: docs/architecture.md and docs/supply-chain.md.
# ovpn-dkms stays on the host (vm-setup/setup-host.sh), not in the image.

# Base image pinned by digest so builds are reproducible. Override
# BASE_IMAGE to rebuild on a newer base. hadolint ignore=DL3006
ARG BASE_IMAGE="ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c"
ARG VERSION="dev"
ARG COMMIT=""

FROM ${BASE_IMAGE}

ARG VERSION
ARG COMMIT

LABEL maintainer="HyperI <opensource@hyperi.io>"
# Scoped as docs/cryptography.md scopes it: the classical suite, OpenVPN path only.
LABEL description="Culvert - OpenVPN + WireGuard, optionally tunnelled over HTTPS, CNSA 2.0 classical suite on the OpenVPN path, OIDC SSO"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.source="https://github.com/hyperi-io/culvert"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL openvpn.version="2.7.0+"
LABEL openvpn.features="DCO,TLS1.3,AEAD,4G-optimized,OIDC-SSO"

ARG DEBIAN_FRONTEND=noninteractive
ARG OPENVPN_MIN_VERSION="2.7.0"
ARG OPENVPN_AUTH_OAUTH2_VERSION="2.3.3"
# Public release checksums. BuildKit's SecretsUsedInArgOrEnv check flags these two only for the AUTH in their name.
ARG OPENVPN_AUTH_OAUTH2_SHA256_AMD64="5c7c455a1edae10570d30f2b58e09722a4912b45cfb2a08200abd492a7aa00ae"
ARG OPENVPN_AUTH_OAUTH2_SHA256_ARM64="be575565fac3af177f1c27a4cec1ebffd24a29bce23fe61023e80e5841c540c7"

# openvpn from its signed apt repo, one pinned key and a version floor: docs/supply-chain.md.
# The pinned key expires in 2030, so re-pin it when it rotates.
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

# openvpn-auth-oauth2 from a pinned, checksum-checked .deb: its apt repo serves
# only latest. dependency-check.yml bumps the version and SHAs.
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

# requirements-docker.txt is a hash-pinned export of uv.lock. Regenerate on any
# uv.lock change with:
#   uv export --frozen --no-dev --no-emit-project --extra otel \
#     --format requirements-txt -o requirements-docker.txt
# No venv by design, so pip's root warning is off.
COPY requirements-docker.txt /tmp/requirements-docker.txt
RUN pip3 install --no-cache-dir --break-system-packages --root-user-action=ignore \
        --require-hashes -r /tmp/requirements-docker.txt \
    && rm /tmp/requirements-docker.txt

# scalo config cascade reads CULVERT_* env vars
ENV ENV_PREFIX=CULVERT

# wstunnel from a pinned, checksum-checked tarball: no apt repo, and the
# upstream image's binary needs a newer glibc.
ARG WSTUNNEL_VERSION="10.7.1"
ARG WSTUNNEL_SHA256_AMD64="fa842ed53fbb14b1c69cd98829f9895d7f8a6b0d562c57c1175851a52cea9ea2"
ARG WSTUNNEL_SHA256_ARM64="99f9506d01d1b4073254609600ec5056dab8dc58aec75c32f6eb0508335a8fd2"
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

RUN mkdir -p /etc/vpn/pki /etc/vpn/server/ccd /etc/vpn/clients \
    /etc/vpn/scripts /etc/vpn/docs /var/log/vpn

# The canonical paths are /etc/vpn and /var/log/vpn, and nothing aliases them.

# Configuration templates (processed by envsubst at runtime)
COPY config/server.conf.template /etc/vpn/server/server.conf.template
COPY config/server-https.conf.template /etc/vpn/server/server-https.conf.template
COPY config/server-tcp.conf.template /etc/vpn/server/server-tcp.conf.template
COPY config/stunnel-server.conf.template /etc/vpn/server/stunnel-server.conf.template

COPY scripts/entrypoint.py /entrypoint.py
COPY scripts/generate-client.py /usr/local/bin/generate-client
COPY scripts/revoke-client.py /usr/local/bin/revoke-client
COPY scripts/update-crl.py /usr/local/bin/update-crl

COPY scripts/lib/ /etc/vpn/scripts/lib/

COPY profiles/ /etc/vpn/profiles/

COPY oauth2-assets/ /etc/openvpn-auth-oauth2/assets/

COPY docs/vpn-client-setup.md /etc/vpn/docs/vpn-client-setup.md

RUN chmod +x /entrypoint.py /usr/local/bin/generate-client \
    /usr/local/bin/revoke-client /usr/local/bin/update-crl

# PYTHONPATH for lib/ module imports (entrypoint is at / but lib/ is under scripts/)
ENV PYTHONPATH="/etc/vpn/scripts"

ARG VERSION
ARG COMMIT
RUN echo "${VERSION}" > /etc/vpn/VERSION \
    && echo "${COMMIT}" > /etc/vpn/COMMIT

VOLUME ["/etc/vpn/pki", "/etc/vpn/server/ccd", "/etc/vpn/clients", "/var/log/vpn"]

# Each port and the switch that opens it: docs/architecture.md.
EXPOSE 1194/udp 1194/tcp 443/tcp 51820/udp 4443/tcp 9000/tcp 9001/tcp 9002/tcp 9090/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/entrypoint.py", "healthcheck"]

ENTRYPOINT ["/entrypoint.py"]
CMD ["server"]
