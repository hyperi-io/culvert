#!/usr/bin/env bash
#  Project:      culvert
#  File:         setup-host.sh
#  Purpose:      Host machine prerequisites for DCO
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Culvert Host VM Setup
# Run this on the VM host BEFORE deploying the container
#
# This script configures HOST-LEVEL settings that cannot be set in the container:
#   1. DCO (Data Channel Offload) kernel module for kernel-space encryption
#   2. TUN and conntrack kernel modules
#   3. Network performance sysctls (BBR, buffer sizes)
#   4. Unattended security upgrades
#   5. Docker (if not installed)
#
# Container handles everything else (OpenVPN, PKI, iptables NAT)
#
# Supported Distros:
#   - Ubuntu 22.04+, 24.04+ (primary)
#   - Debian 11+, 12+
#   - Amazon Linux 2023
#
# Usage: sudo ./setup-host.sh
#
# Requirements:
#   - Linux kernel 5.4+ (6.x recommended for DCO)
#   - Root access
#   - Internet connectivity

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${CYAN}=== $* ===${NC}"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

#===============================================================================
# Detect Distribution
#===============================================================================
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_CODENAME="${VERSION_CODENAME:-}"
        DISTRO_PRETTY="$PRETTY_NAME"
    elif [[ -f /etc/system-release ]]; then
        # Amazon Linux
        if grep -q "Amazon Linux" /etc/system-release; then
            DISTRO_ID="amzn"
            DISTRO_CODENAME=""
            DISTRO_PRETTY=$(cat /etc/system-release)
        fi
    else
        log_error "Cannot detect distribution"
        exit 1
    fi
}

detect_distro

log_section "Culvert Host VM Setup"

# Display system info
log_info "Hostname: $(hostname)"
log_info "Kernel: $(uname -r)"
log_info "OS: $DISTRO_PRETTY"
log_info "Distro ID: $DISTRO_ID"

#===============================================================================
# Package Manager Detection
#===============================================================================
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    PKG_INSTALL="apt-get install -y"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_INSTALL="dnf install -y"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_INSTALL="yum install -y"
else
    log_error "No supported package manager found (apt, dnf, yum)"
    exit 1
fi

log_info "Package manager: $PKG_MANAGER"

#===============================================================================
# OpenVPN DCO (Data Channel Offload) Kernel Module
# This is the KEY performance optimization - moves encryption to kernel space
#===============================================================================
log_section "Installing OpenVPN DCO Kernel Module"

install_dco_ubuntu_debian() {
    # Add OpenVPN official repository for DCO DKMS module
    if [[ ! -f /etc/apt/sources.list.d/openvpn.list ]]; then
        log_info "Adding OpenVPN official repository..."
        $PKG_INSTALL ca-certificates curl gnupg lsb-release
        mkdir -p /etc/apt/keyrings
        # Fetch over pinned TLS, verify the key fingerprint FAIL-CLOSED before
        # trusting it (a bare curl | gpg --dearmor imports whatever the endpoint
        # serves). Key 30EB F4E7 ... E158 C569 (Samuli Seppanen, exp 2030).
        curl --proto '=https' --tlsv1.2 -fsSL --max-time 30 \
            https://swupdate.openvpn.net/repos/repo-public.gpg -o /tmp/openvpn-repo.gpg
        if ! gpg --show-keys --with-colons /tmp/openvpn-repo.gpg \
             | awk -F: '$1=="fpr"{print $10}' \
             | grep -qx 30EBF4E73CCE63EEE124DD278E6DA8B4E158C569; then
            log_error "OpenVPN repo key fingerprint mismatch - refusing to trust it"
            rm -f /tmp/openvpn-repo.gpg
            exit 1
        fi
        gpg --dearmor -o /etc/apt/keyrings/openvpn.gpg /tmp/openvpn-repo.gpg
        rm -f /tmp/openvpn-repo.gpg

        # Get codename - handle both Ubuntu and Debian
        local codename
        codename=$(lsb_release -cs 2>/dev/null || echo "$DISTRO_CODENAME")

        # Map Debian codenames if needed
        case "$codename" in
            bookworm|trixie) codename="bookworm" ;;  # Debian 12+
            bullseye) codename="bullseye" ;;          # Debian 11
            noble|jammy|focal) ;;                     # Ubuntu - use as-is
            *) codename="bookworm" ;;                 # Default fallback
        esac

        echo "deb [signed-by=/etc/apt/keyrings/openvpn.gpg] https://build.openvpn.net/debian/openvpn/stable $codename main" > /etc/apt/sources.list.d/openvpn.list
        apt-get update
    fi

    # Install DCO DKMS module (compiles against current kernel)
    log_info "Installing openvpn-dco-dkms..."

    # Install kernel headers for DKMS compilation
    if [[ "$DISTRO_ID" == "ubuntu" ]]; then
        $PKG_INSTALL linux-headers-"$(uname -r)" || $PKG_INSTALL linux-headers-generic || true
    else
        $PKG_INSTALL linux-headers-"$(uname -r)" || $PKG_INSTALL linux-headers-amd64 || true
    fi

    $PKG_INSTALL openvpn-dco-dkms || {
        log_warn "openvpn-dco-dkms not available - DCO will use in-tree module if present"
    }
}

install_dco_amazon_linux() {
    log_info "Amazon Linux detected - checking for in-tree DCO module..."

    # Amazon Linux 2023 may have DCO in-tree with newer kernels
    # Install kernel-devel for any DKMS needs
    $PKG_INSTALL kernel-devel-"$(uname -r)" || $PKG_INSTALL kernel-devel || true

    # Try to load in-tree DCO module
    modprobe ovpn-dco-v2 2>/dev/null || modprobe openvpn-dco 2>/dev/null || {
        log_warn "DCO module not available on Amazon Linux"
        log_warn "Will use userspace encryption (still functional, slightly slower)"
    }
}

# Install DCO based on distro
case "$DISTRO_ID" in
    ubuntu|debian)
        install_dco_ubuntu_debian
        ;;
    amzn|amazonlinux)
        install_dco_amazon_linux
        ;;
    *)
        log_warn "Unknown distro '$DISTRO_ID' - attempting generic DCO setup"
        modprobe ovpn-dco-v2 2>/dev/null || modprobe openvpn-dco 2>/dev/null || true
        ;;
esac

# Try to load DCO module
log_info "Loading DCO kernel module..."
modprobe ovpn-dco-v2 2>/dev/null || modprobe openvpn-dco 2>/dev/null || {
    log_warn "DCO module not available - will fall back to userspace encryption"
    log_warn "This is normal on some kernels. Container will still work."
}

# Ensure DCO loads at boot (works on all distros)
MODULES_FILE="/etc/modules-load.d/openvpn-dco.conf"
if [[ ! -f "$MODULES_FILE" ]]; then
    echo "ovpn-dco-v2" > "$MODULES_FILE"
    log_info "Created $MODULES_FILE for boot"
fi

# Verify DCO status
if lsmod | grep -q "ovpn_dco"; then
    log_info "DCO module loaded successfully!"
    log_info "  Encryption will be offloaded to kernel space"
else
    log_warn "DCO module not loaded - will use userspace encryption"
fi

#===============================================================================
# Core Kernel Modules (TUN, conntrack)
#===============================================================================
log_section "Configuring Core Kernel Modules"

# Create modules-load.d config for all required modules
cat > /etc/modules-load.d/openvpn.conf << 'EOF'
# OpenVPN required kernel modules
tun
nf_conntrack
EOF

# Load modules now
modprobe tun
log_info "TUN module: $(lsmod | grep -q "^tun" && echo "loaded" || echo "not loaded")"

modprobe nf_conntrack 2>/dev/null || true
log_info "nf_conntrack module: $(lsmod | grep -q "nf_conntrack" && echo "loaded" || echo "not loaded")"

#===============================================================================
# Host Network Sysctls
# These MUST be on the host - container can't set these
#===============================================================================
log_section "Configuring Host Network Sysctls"

SYSCTL_FILE="/etc/sysctl.d/99-openvpn-host.conf"
cat > "$SYSCTL_FILE" << 'EOF'
# Culvert Host Configuration
# These settings MUST be on the host for DCO and network performance
# Container-level sysctls are set via docker-compose

#===============================================================================
# TCP BBR Congestion Control
# Critical for VPN performance, especially over 4G/mobile networks
# BBR is 2700x faster than CUBIC on lossy, high-latency links
#===============================================================================
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

#===============================================================================
# Network Buffer Sizes
# Required for high-latency connections (mobile, satellite, intercontinental)
# 25MB max allows optimal performance up to ~200ms latency at 1Gbps
#===============================================================================
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# TCP buffer auto-tuning (min, default, max)
net.ipv4.tcp_rmem = 4096 1048576 26214400
net.ipv4.tcp_wmem = 4096 1048576 26214400

#===============================================================================
# Connection Tracking
# High limit for many concurrent VPN clients
#===============================================================================
net.netfilter.nf_conntrack_max = 1048576

#===============================================================================
# IP Forwarding (also set in container, but good to have on host)
#
# IPv4 only. Culvert's routing control is enforced with iptables, so
# forwarded IPv6 would bypass client isolation, the egress allow-list and
# the reverse-admin gate.
#===============================================================================
net.ipv4.ip_forward = 1

#===============================================================================
# UDP Optimizations (OpenVPN uses UDP primarily)
#===============================================================================
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

#===============================================================================
# TCP Optimizations
#===============================================================================
# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1
# Enable TCP timestamps
net.ipv4.tcp_timestamps = 1
# Enable SACK
net.ipv4.tcp_sack = 1
# Disable slow start after idle
net.ipv4.tcp_slow_start_after_idle = 0
EOF

sysctl -p "$SYSCTL_FILE"
log_info "Applied host sysctls"

# Verify BBR is active
if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    log_info "TCP BBR congestion control: active"
else
    log_warn "TCP BBR not active - check kernel support"
fi

#===============================================================================
# TUN Interface Queue Length
# Increase from default 100 to 1000 to prevent packet drops
#===============================================================================
log_section "Configuring TUN Queue Length"

# Create udev rule for tun devices (works on all distros)
mkdir -p /etc/udev/rules.d
cat > /etc/udev/rules.d/99-openvpn-tun.rules << 'EOF'
# Set txqueuelen for TUN devices to prevent packet drops
KERNEL=="tun*", RUN+="/sbin/ip link set %k txqueuelen 1000"
EOF

udevadm control --reload-rules 2>/dev/null || true
log_info "Created udev rule for TUN txqueuelen=1000"

#===============================================================================
# Unattended Upgrades (Security Auto-patching)
#===============================================================================
log_section "Configuring Unattended Upgrades"

case "$DISTRO_ID" in
    ubuntu|debian)
        $PKG_INSTALL unattended-upgrades apt-listchanges

        cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "Docker:${distro_codename}";
    "origin=build.openvpn.net";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

        cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

        systemctl enable unattended-upgrades
        systemctl restart unattended-upgrades
        log_info "Unattended upgrades configured (apt)"
        ;;

    amzn|amazonlinux)
        # Amazon Linux uses dnf-automatic
        $PKG_INSTALL dnf-automatic

        # Configure for security updates only
        cat > /etc/dnf/automatic.conf << 'EOF'
[commands]
upgrade_type = security
random_sleep = 0
download_updates = yes
apply_updates = yes

[emitters]
system_name = None
emit_via = stdio

[email]
email_from = root@localhost
email_to = root
email_host = localhost

[command]
[command_email]
[base]
debuglevel = 1
EOF

        systemctl enable dnf-automatic.timer
        systemctl start dnf-automatic.timer
        log_info "dnf-automatic configured for security updates"
        ;;

    *)
        log_warn "Auto-updates not configured for distro: $DISTRO_ID"
        ;;
esac

#===============================================================================
# Docker Installation
#===============================================================================
log_section "Checking Docker"

install_docker_ubuntu_debian() {
    # Distro packages only. Piping a remote script into a root shell is
    # never acceptable (get.docker.com included). docker.io is current
    # enough for running the culvert container.
    if ! command -v docker >/dev/null 2>&1; then
        log_info "Installing Docker from the distro repository..."
        $PKG_INSTALL docker.io
        systemctl enable docker
        systemctl start docker
        log_info "Docker installed: $(docker --version)"
    else
        log_info "Docker already installed: $(docker --version)"
    fi

    # Ensure the compose plugin is available (package name differs:
    # ubuntu ships docker-compose-v2, debian docker-compose-plugin via
    # backports, both fall back to docker-compose)
    if ! docker compose version >/dev/null 2>&1; then
        log_info "Installing Docker Compose plugin..."
        $PKG_INSTALL docker-compose-v2 \
            || $PKG_INSTALL docker-compose-plugin \
            || $PKG_INSTALL docker-compose \
            || log_warn "Install docker compose manually: https://docs.docker.com/compose/install/"
    fi
}

install_docker_amazon_linux() {
    if ! command -v docker >/dev/null 2>&1; then
        log_info "Installing Docker on Amazon Linux..."
        $PKG_INSTALL docker
        systemctl enable docker
        systemctl start docker
        log_info "Docker installed: $(docker --version)"
    else
        log_info "Docker already installed: $(docker --version)"
    fi

    # Compose plugin from the distro package (Amazon Linux 2023 ships
    # docker-compose-plugin). Where no package exists, install a pinned
    # binary and check its checksum - do not pipe an installer into a shell.
    if ! docker compose version >/dev/null 2>&1; then
        log_info "Installing Docker Compose plugin from the distro..."
        $PKG_INSTALL docker-compose-plugin \
            || log_warn "No docker-compose-plugin package - install a pinned, checksum-verified compose binary manually: https://docs.docker.com/compose/install/"
    fi
}

case "$DISTRO_ID" in
    ubuntu|debian)
        install_docker_ubuntu_debian
        ;;
    amzn|amazonlinux)
        install_docker_amazon_linux
        ;;
    *)
        log_warn "Docker installation not automated for: $DISTRO_ID"
        log_warn "Please install Docker manually"
        ;;
esac

# Verify docker compose is available (either plugin or standalone)
if docker compose version >/dev/null 2>&1; then
    log_info "Docker Compose: $(docker compose version --short 2>/dev/null)"
elif command -v docker-compose >/dev/null 2>&1; then
    log_info "Docker Compose (standalone): $(docker-compose --version 2>/dev/null)"
else
    log_warn "Docker Compose not found - please install manually"
fi

#===============================================================================
# Summary
#===============================================================================
log_section "Host Setup Complete"

echo ""
echo "Configuration Summary:"
echo "  - OS: $DISTRO_PRETTY"
echo "  - DCO module: $(lsmod | grep -q 'ovpn_dco' && echo 'LOADED (kernel encryption)' || echo 'not loaded (userspace fallback)')"
echo "  - TCP BBR: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "  - Buffer max: $(sysctl -n net.core.rmem_max 2>/dev/null) bytes"
echo "  - Conntrack max: $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)"
echo "  - Docker: $(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',' || echo 'not installed')"
echo ""
log_info "Host VM is ready for OpenVPN container deployment"
echo ""
echo "Next steps:"
echo "  1. Copy the openvpn/ directory to this host"
echo "  2. Create .env file from .env.example"
echo "  3. Run: docker compose up -d"
echo "  4. Generate clients: docker compose exec openvpn generate-client <name>"
echo ""
