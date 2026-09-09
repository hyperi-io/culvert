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

import re
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

# Container paths the server does NOT read. See TestCanonicalPaths.
LEGACY_CONTAINER_PATHS = (
    "/etc/openvpn/pki",
    "/etc/openvpn/clients",
    "/etc/openvpn/server",
    "/etc/openvpn/oauth2-tls",
    # No trailing slash: a mount target has none, which is how two compose
    # files kept mounting the log directory at a path nothing writes.
    "/var/log/openvpn",
)


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


class TestCanonicalPaths:
    """Nothing may point a mount or a config value at the legacy /etc/openvpn.

    The server reads /etc/vpn. /etc/openvpn is a real directory owned by the
    openvpn package, so a mount there does not reach the server - it just sits
    somewhere nothing looks. That is how the shipped compose file mounted PKI at
    a path the server never read, quietly minting a fresh CA on every recreate
    and invalidating every client config already issued.

    Named exactly, rather than by prefix, because two lookalikes are correct and
    must not be flagged: /etc/openvpn-auth-oauth2 is where openvpn-auth-oauth2
    keeps its OWN config, and /etc/openvpn/client (singular) is the standard
    place a Linux CLIENT keeps its profile - the client-setup guide is right to
    say so, since that path is on the reader's machine, not in this container.
    """

    def test_no_tracked_file_uses_a_legacy_container_path(self):
        this_file = Path(__file__).resolve()
        offenders = []
        for path in _tracked_text_files():
            if path.resolve() == this_file:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, FileNotFoundError):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if any(legacy in line for legacy in LEGACY_CONTAINER_PATHS):
                    rel = path.relative_to(REPO_ROOT)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")

        assert not offenders, (
            "legacy container path referenced in tracked files - the server reads"
            " /etc/vpn and /var/log/vpn:\n" + "\n".join(offenders)
        )


@pytest.fixture(scope="module")
def values() -> dict:
    return _load(CHART_DIR / "values.yaml")


@pytest.fixture(scope="module")
def chart() -> dict:
    return _load(CHART_DIR / "Chart.yaml")


def _changelog_versions() -> list[tuple[int, int, int]]:
    """Every `## [X.Y.Z]` release heading in CHANGELOG.md, as sortable tuples."""
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return [
        (int(m[0]), int(m[1]), int(m[2]))
        for m in re.findall(r"^## \[(\d+)\.(\d+)\.(\d+)\]", text, re.MULTILINE)
    ]


def _latest_release_tag() -> str | None:
    """The highest vX.Y.Z tag git knows about, or None when there are none.

    None is the honest answer in a shallow clone: `actions/checkout` fetches no
    tags unless asked, and inventing a comparison there would fail a test on
    what the checkout omitted rather than on anything in the tree.
    """
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "tag", "--list", "v*", "--sort=-v:refname"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=60,
    )
    tags = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return tags[0] if tags else None


class TestImageReference:
    """A plain `helm install` must resolve to an image that exists."""

    def test_app_version_tracks_the_version_file(self, chart):
        """image.tag defaults to appVersion, so a stale one is ImagePullBackOff."""
        version = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        assert chart["appVersion"] == f"v{version.lstrip('v')}"
        assert chart["version"] == version.lstrip("v")

    def test_app_version_is_not_behind_the_changelog(self, chart):
        """The in-tree guard, for a checkout with no tags.

        The tag check below is the precise one, and it skips wherever
        `actions/checkout` was not asked for tags -- which is CI, the one place
        a stale chart most needs stopping. CHANGELOG.md is committed by the
        release job, so it is in the tree whatever the fetch depth.

        Weaker on purpose: it only proves the chart is not BEHIND a release the
        changelog already records, so being ahead (just after a backfill) is
        fine. It would still have caught the drift this test was written for --
        the chart sat at 2.1.10 while the changelog recorded 2.1.12.
        """
        released = _changelog_versions()
        if not released:
            pytest.skip("no released versions recorded in CHANGELOG.md")

        newest = max(released)
        actual = tuple(
            int(part) for part in chart["appVersion"].lstrip("v").split(".")[:3]
        )
        assert actual >= newest, (
            f"chart appVersion {chart['appVersion']} is behind"
            f" {'.'.join(str(n) for n in newest)}, the newest release in"
            " CHANGELOG.md, so `helm install` deploys an image that old"
        )

    def test_app_version_tracks_the_latest_release(self, chart):
        """The chart must not point at an image older than the last release.

        Agreeing with VERSION is not enough: the release pipeline stamps VERSION
        only for the build and commits just the CHANGELOG, so VERSION and
        Chart.yaml stay in step with each other while both fall behind what was
        actually published. That is how the chart shipped seven releases stale
        (fixed in dab7919) and then three releases stale again.

        Fix a failure by bumping VERSION to the tag and regenerating:
        `python scripts/generate-deploy-artefacts.py`.
        """
        latest = _latest_release_tag()
        if latest is None:
            pytest.skip("no release tags in this clone - nothing to compare against")

        assert chart["appVersion"] == latest, (
            f"chart appVersion {chart['appVersion']} is not the latest release"
            f" {latest}, so `helm install` deploys an image that old"
        )


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


class TestWireGuardReplicaGuard:
    """WireGuard has no shared-key path, so it cannot be scaled out.

    Nothing in lib/pki.py sources WireGuard material, so every replica mints its
    own server keypair and keeps its own allocations.json: a client config
    reaches exactly one pod and the tunnel addresses collide. pkiSecret does not
    excuse it -- that Secret carries no WireGuard key -- so this guard has to be
    independent of the two beside it.
    """

    def test_guard_is_present_and_independent_of_the_pki_guards(self):
        text = (CHART_DIR / "templates" / "deployment.yaml").read_text(encoding="utf-8")
        assert "CULVERT_PROTOCOL" in text, (
            "the deployment template never reads CULVERT_PROTOCOL, so a"
            " multi-replica WireGuard install renders without complaint"
        )
        assert 'list "wireguard" "both"' in text, (
            "the guard does not cover both WireGuard-carrying protocol values"
        )

    def test_guard_reads_the_autoscaler_ceiling(self):
        """An HPA that CAN reach 2 replicas is already broken for WireGuard."""
        text = (CHART_DIR / "templates" / "deployment.yaml").read_text(encoding="utf-8")
        wg_guard = text.split("$wg :=")[1]
        assert "$replicas" in wg_guard, (
            "the WireGuard guard does not use the shared $replicas value, so it"
            " does not inherit the autoscaler-ceiling handling"
        )

    @pytest.mark.parametrize("starter", STARTERS)
    def test_multi_replica_starters_do_not_enable_wireguard(self, starter):
        """A starter that trips the chart's own guard is uninstallable."""
        values_file = _load(CHART_DIR / starter)
        replicas = values_file.get("autoscaling", {}).get(
            "maxReplicas", values_file.get("replicaCount", 1)
        )
        if int(replicas) < 2:
            pytest.skip(f"{starter} runs a single replica")
        protocol = values_file.get("env", {}).get("CULVERT_PROTOCOL", "openvpn")
        assert protocol not in ("wireguard", "both"), (
            f"{starter} scales to {replicas} replicas with"
            f" CULVERT_PROTOCOL={protocol}; each would mint its own WireGuard"
            " server key, so the chart's guard rejects the install"
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
