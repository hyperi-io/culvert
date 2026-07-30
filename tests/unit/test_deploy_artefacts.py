#  Project:      culvert
#  File:         test_deploy_artefacts.py
#  Purpose:      Guard the shipped deployment artefacts and tracked-tree hygiene
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Checks on what culvert actually ships, runnable without a cluster.

The cluster tier in tests/k8s/ proves the chart works on a real cluster, but it
needs a kubeconfig and never runs in CI. These assertions cover the failures
that are visible in the shipped files alone - the ones that would otherwise be
found by whoever runs `helm install` first, or read by whoever clones the repo.
"""

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHART_DIR = REPO_ROOT / "deploy" / "helm" / "culvert"
STARTERS = ("values-k8s-scale.yaml", "values-edge-fleet.yaml")

# Decommissioned org libraries. culvert runs on scalo, their Apache-2.0
# successor, and has done since the rebrand. A reference in a tracked file
# either points a reader at something that no longer exists or, worse, names a
# proprietary internal library from a public Apache-2.0 repo.
RETIRED_DEPENDENCIES = (
    "hyperi-pylib",
    "hyperi_pylib",
    "hyperi-rustlib",
    "hyperi_rustlib",
)

# Text files only: a match inside a PNG is noise, and binary assets cannot
# reference a dependency in any meaningful way.
_BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2"}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _tracked_text_files() -> list[Path]:
    """Every tracked file git knows about, minus binary assets."""
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=60,
    )
    return [
        REPO_ROOT / name
        for name in result.stdout.split("\0")
        if name and Path(name).suffix.lower() not in _BINARY_SUFFIXES
    ]


class TestRetiredDependencies:
    """Nothing culvert ships may name a decommissioned org library."""

    def test_no_tracked_file_mentions_a_retired_library(self):
        """hyperi-pylib and hyperi-rustlib were replaced by scalo.

        Scanning the tracked tree rather than a hand-kept file list, because the
        last few strays turned up in a changelog entry and a doc subtitle - not
        anywhere anyone would think to look.
        """
        this_file = Path(__file__).resolve()
        offenders = []
        for path in _tracked_text_files():
            # This module names them in order to look for them.
            if path.resolve() == this_file:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, FileNotFoundError):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if any(name in line for name in RETIRED_DEPENDENCIES):
                    rel = path.relative_to(REPO_ROOT)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")

        assert not offenders, (
            "retired library referenced in tracked files:\n" + "\n".join(offenders)
        )


@pytest.fixture(scope="module")
def values() -> dict:
    return _load(CHART_DIR / "values.yaml")


@pytest.fixture(scope="module")
def chart() -> dict:
    return _load(CHART_DIR / "Chart.yaml")


class TestImageReference:
    """A plain `helm install` must resolve to an image that exists."""

    def test_app_version_tracks_the_version_file(self, chart):
        """image.tag defaults to appVersion, so a stale one is ImagePullBackOff."""
        version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        assert chart["appVersion"] == f"v{version.lstrip('v')}"
        assert chart["version"] == version.lstrip("v")


class TestCapabilities:
    """The pod must hold every capability the VPN data plane needs."""

    def test_privilege_drop_capabilities_are_granted(self, values):
        """OpenVPN drops to user nobody at startup and exits 1 if it cannot.

        NET_ADMIN alone is not enough: retaining it across the drop needs
        SETPCAP, and the drop itself needs SETUID and SETGID.
        """
        added = values["securityContext"]["capabilities"]["add"]
        for cap in ("NET_ADMIN", "SETPCAP", "SETGID", "SETUID"):
            assert cap in added, f"{cap} missing from securityContext.capabilities"

    def test_non_root_floor_is_not_reimposed(self, values):
        """OpenVPN and wg-quick create the tun device and program routing."""
        assert "runAsNonRoot" not in values["podSecurityContext"]

    def test_unsafe_sysctl_is_not_requested_by_default(self, values):
        """A kubelet without --allowed-unsafe-sysctls rejects the pod outright."""
        assert "sysctls" not in values["podSecurityContext"]

    def test_tun_device_is_passed_through(self, values):
        assert values["tunDevice"]["enabled"] is True

    def test_ip_forwarding_is_enabled_by_default(self, values):
        """Off, the server accepts clients and forwards none of their traffic."""
        assert values["ipForward"]["enabled"] is True

    def test_ip_forward_init_container_is_privileged(self):
        """/proc/sys is read-only to an unprivileged container, capabilities or not."""
        text = (CHART_DIR / "templates" / "deployment.yaml").read_text(encoding="utf-8")
        assert "net.ipv4.ip_forward=1" in text
        assert "privileged: true" in text


class TestObservabilityIsNotExposedByAccident:
    """One Service carries the VPN ports and the unauthenticated :9090."""

    @pytest.mark.parametrize("starter", STARTERS)
    def test_loadbalancer_starters_ship_fail_closed(self, starter):
        """A LoadBalancer with no source ranges publishes /metrics to the world.

        Both starters carry a deliberately invalid placeholder so the API server
        rejects the Service until an operator names their own CIDRs.
        """
        service = _load(CHART_DIR / starter)["service"]
        if service.get("type") != "LoadBalancer":
            pytest.skip(f"{starter} does not use a LoadBalancer")
        ranges = service.get("loadBalancerSourceRanges") or []
        assert ranges, f"{starter} exposes an unrestricted LoadBalancer"
        assert any("REPLACE-ME" in str(r) for r in ranges), (
            f"{starter} ships a usable source range - it must not install"
            " until the operator supplies their own"
        )


class TestFlowAffinity:
    """Tunnel state is per-pod, so a flow must not move between replicas."""

    @pytest.mark.parametrize("starter", STARTERS)
    def test_multi_replica_starters_pin_flows(self, starter):
        values_file = _load(CHART_DIR / starter)
        replicas = values_file.get("autoscaling", {}).get(
            "minReplicas", values_file.get("replicaCount", 1)
        )
        if int(replicas) < 2:
            pytest.skip(f"{starter} runs a single replica - affinity is moot")
        service = values_file["service"]
        assert (
            service.get("sessionAffinity") == "ClientIP"
            or service.get("externalTrafficPolicy") == "Local"
        ), f"{starter} runs {replicas} replicas with no flow pinning"

    @pytest.mark.parametrize("starter", STARTERS)
    def test_multi_replica_starters_use_external_pki(self, starter):
        """Local PKI would give each replica its own CA; the chart refuses it."""
        values_file = _load(CHART_DIR / starter)
        replicas = values_file.get("autoscaling", {}).get(
            "minReplicas", values_file.get("replicaCount", 1)
        )
        if int(replicas) < 2:
            pytest.skip(f"{starter} runs a single replica")
        assert values_file["env"].get("CULVERT_PKI_MODE") == "external", (
            f"{starter} runs {replicas} replicas without external PKI, so the"
            " chart's own guard makes it uninstallable"
        )


class TestSharedPkiMaterial:
    """More than one replica only works when every one holds the same material."""

    def test_guard_counts_the_autoscaler_ceiling_not_its_floor(self):
        """minReplicas defaults to 1, so a floor check waves an HPA straight past.

        `--set autoscaling.enabled=true` alone rendered a Deployment plus an HPA
        that could reach 10 local-PKI replicas, each minting its own CA - the
        exact failure the guard's message describes preventing.
        """
        text = (CHART_DIR / "templates" / "deployment.yaml").read_text(encoding="utf-8")
        assert "autoscaling.maxReplicas" in text, (
            "the replica guard does not read autoscaling.maxReplicas, so an HPA"
            " can scale past it unchecked"
        )
        assert "autoscaling.minReplicas" not in text, (
            "the replica guard still reads minReplicas, which is the floor and"
            " not what the autoscaler can reach"
        )

    def test_pki_secret_is_off_by_default(self, values):
        """The five-minute path is a single server minting its own PKI."""
        assert values["pkiSecret"] == ""
        assert values["pkiSecretMountPath"].startswith("/")

    @pytest.mark.parametrize("starter", STARTERS)
    def test_multi_replica_starters_document_the_requirement(self, starter):
        """The starters cannot name a Secret, so the install command must."""
        values_file = _load(CHART_DIR / starter)
        replicas = values_file.get("autoscaling", {}).get(
            "minReplicas", values_file.get("replicaCount", 1)
        )
        if int(replicas) < 2:
            pytest.skip(f"{starter} runs a single replica")
        text = (CHART_DIR / starter).read_text(encoding="utf-8")
        assert "pkiSecret" in text, (
            f"{starter} runs {replicas} replicas but never mentions pkiSecret,"
            " so the chart's guard will reject it with no hint in the file"
        )


class TestLogging:
    """A pod that dies must say why in `kubectl logs`."""

    def test_chart_sends_openvpn_log_to_stdout(self, values):
        """The image default writes it to a file inside the dead container."""
        assert values["env"]["CULVERT_LOG_MODE"] == "stdout"


class TestComposeFragment:
    """The generated fragment must describe a port something actually binds."""

    def test_vpn_port_is_published_as_udp(self):
        text = (REPO_ROOT / "deploy" / "compose" / "culvert.yaml").read_text(
            encoding="utf-8"
        )
        assert "1194:1194/udp" in text
