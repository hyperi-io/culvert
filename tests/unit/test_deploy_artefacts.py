#  Project:      culvert
#  File:         test_deploy_artefacts.py
#  Purpose:      Guard the shipped deployment artefacts and tracked-tree hygiene
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Checks on what culvert actually ships, runnable without a cluster.

The chart is published, not committed, so what an operator installs is the
contract plus the values docs/use-case-kubernetes.md documents. The cluster tier
in tests/k8s/ proves those work on a real cluster, but it needs a kubeconfig and
never runs in CI. These assertions cover the failures that are visible in the
contract, the documented values and the tracked tree alone - the ones that would
otherwise be found by whoever installs the chart first, or reads the repo.
"""

import dataclasses
import subprocess
from pathlib import Path, PurePosixPath

import doc_values
import pytest
from lib.config import Config
from lib.deployment import deployment_contract

REPO_ROOT = Path(__file__).resolve().parents[2]

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

# The documented opt-in listeners: port name -> the Config fields that carry its
# default port and the switch that turns the feature on. The walkthrough's
# extraPorts and its switch table are checked against these.
OPT_IN_LISTENERS = {
    "openvpn-tcp": ("tcp_port", "tcp_enabled"),
    "openvpn-https": ("https_port", "https_enabled"),
    "wg-https": ("wg_https_tunnel_port", "wg_https_tunnel_enabled"),
    "oauth2-udp": ("oauth2_udp_port", "oauth2_enabled"),
    "oauth2-https": ("oauth2_https_port", "oauth2_enabled"),
    "oauth2-tcp": ("oauth2_tcp_port", "oauth2_enabled"),
    "client-download": ("client_download_port", "client_download_enabled"),
}


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
            except UnicodeDecodeError, FileNotFoundError:
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
            except UnicodeDecodeError, FileNotFoundError:
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
def contract():
    return deployment_contract()


@pytest.fixture(scope="module")
def install() -> dict:
    """The install values from the Kubernetes walkthrough."""
    return doc_values.install_values()


@pytest.fixture(scope="module")
def external_pki() -> dict:
    """The external PKI values from the Kubernetes walkthrough."""
    return doc_values.external_pki_values()


def _volume(values: dict, name: str) -> dict:
    return next(v for v in values["extraVolumes"] if v["name"] == name)


def _mount(values: dict, name: str) -> dict:
    return next(m for m in values["extraVolumeMounts"] if m["name"] == name)


def _documented_env(values: dict) -> dict[str, str]:
    """The documented extraEnv, minus CULVERT_PROFILE.

    A profile name loads /etc/vpn/profiles/<name>.yaml and exits when it is
    absent, and the file only exists inside the pod.
    """
    return {
        name: str(value)
        for name, value in values["extraEnv"].items()
        if name != "CULVERT_PROFILE"
    }


class TestPodSurface:
    """The pod must hold everything the VPN data plane needs.

    The chart renders only what the contract names, so the root identity and the
    capabilities come from the contract, and the tun device and ip_forward come
    from the documented values.
    """

    def test_privilege_drop_capabilities_are_granted(self, contract):
        """OpenVPN drops to user nobody at startup and exits 1 if it cannot.

        NET_ADMIN alone is not enough: retaining it across the drop needs
        SETPCAP, and the drop itself needs SETUID and SETGID.
        """
        granted = set(contract.security.capabilities_add)
        assert {"NET_ADMIN", "SETPCAP", "SETGID", "SETUID"} <= granted

    def test_runs_as_root(self, contract):
        """OpenVPN and wg-quick create the tun device and program routing."""
        assert contract.security.run_as_user == 0

    def test_tun_device_is_passed_through(self, install):
        assert _volume(install, "tun")["hostPath"] == {
            "path": "/dev/net/tun",
            "type": "CharDevice",
        }
        assert _mount(install, "tun")["mountPath"] == "/dev/net/tun"

    def test_ip_forward_is_set_by_a_privileged_init_container(self, install):
        """/proc/sys is read-only to an unprivileged container, capabilities or not.

        Off, the server accepts clients and forwards none of their traffic.
        """
        (init,) = install["initContainers"]
        assert init["command"] == ["sysctl", "-w", "net.ipv4.ip_forward=1"]
        assert init["securityContext"]["privileged"] is True

    def test_unsafe_sysctl_is_not_requested(self, install):
        """A kubelet without --allowed-unsafe-sysctls rejects the pod outright."""
        assert "sysctls" not in install.get("podSecurityContext", {})


class TestSingleReplica:
    """The walkthrough says one replica, so the contract has to say it too."""

    def test_the_contract_is_a_singleton(self, contract):
        """The chart renders one Recreate pod and no autoscaler for a singleton.

        WireGuard mints its server key in the pod, so a second pod would issue
        client configs the first rejects.
        """
        assert contract.singleton is True


class TestConfigFile:
    """`config` has to reach the server, and the server has to log somewhere."""

    def test_config_is_mounted_as_a_single_file(self, install):
        assert install["configMount"]["subPath"] is True

    def test_profile_names_the_mounted_file(self, install, contract):
        """CULVERT_PROFILE=<name> loads /etc/vpn/profiles/<name>.yaml.

        Without it the mounted file is never read.
        """
        mounted = PurePosixPath(contract.config_mount_path)
        assert mounted.parent == PurePosixPath("/etc/vpn/profiles")
        assert install["extraEnv"]["CULVERT_PROFILE"] == mounted.stem

    def test_log_goes_to_stdout(self, install):
        """The image default writes it to a file inside a dead container."""
        assert install["extraEnv"]["CULVERT_LOG_MODE"] == "stdout"


class TestOptInListeners:
    """The documented listener ports must be the ones the server binds."""

    def test_every_opt_in_listener_is_documented(self, install):
        documented = {port["name"] for port in install["extraPorts"]}
        assert documented == set(OPT_IN_LISTENERS)

    @pytest.mark.parametrize("name", OPT_IN_LISTENERS)
    def test_port_is_the_config_default(self, install, name):
        port = next(p for p in install["extraPorts"] if p["name"] == name)
        port_field, _ = OPT_IN_LISTENERS[name]
        assert port["port"] == getattr(Config(), port_field)
        assert port["protocol"] == "TCP"
        assert port["public"] is True

    @pytest.mark.parametrize("name", OPT_IN_LISTENERS)
    def test_switch_is_a_config_flag_and_is_in_the_table(self, name):
        _, switch_field = OPT_IN_LISTENERS[name]
        assert isinstance(getattr(Config(), switch_field), bool)
        assert f"CULVERT_{switch_field.upper()}=true" in doc_values.doc_text()

    def test_names_do_not_repeat_the_contract_ports(self, install, contract):
        """The library renders the contract's ports, so a repeat is a duplicate."""
        names = [port["name"] for port in install["extraPorts"]]
        assert len(names) == len(set(names))
        assert not set(names) & {port.name for port in contract.extra_ports}

    def test_the_metrics_port_is_not_public(self, install, contract):
        """The LoadBalancer must not publish /livez, /readyz or /metrics."""
        assert all(p["port"] != contract.metrics_port for p in install["extraPorts"])


class TestDocumentedEnvironment:
    """Config must accept the environment the walkthrough tells an operator to set."""

    def test_install_environment_is_accepted(self, install, clean_env, monkeypatch):
        for name, value in _documented_env(install).items():
            monkeypatch.setenv(name, value)
        cfg = Config.from_settings()
        cfg.validate()
        assert cfg.server_cn == install["extraEnv"]["CULVERT_SERVER_CN"]
        assert cfg.log_mode == "stdout"

    def test_external_pki_environment_is_accepted(
        self, install, external_pki, clean_env, monkeypatch
    ):
        env = {**_documented_env(install), **_documented_env(external_pki)}
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        cfg = Config.from_settings()
        cfg.validate()
        assert cfg.pki_mode == "external"
        assert cfg.secrets_provider == "file"
        assert cfg.secrets_ca_cert_path == env["CULVERT_SECRETS_CA_CERT_PATH"]
        assert cfg.secrets_server_key_path == env["CULVERT_SECRETS_SERVER_KEY_PATH"]


class TestExternalPki:
    """The file provider reads a mounted Secret, so the mount has to line up."""

    def test_lists_carry_the_tun_entries(self, external_pki):
        """Helm replaces a list rather than merging it.

        A block that set only the Secret volume would drop the tun device from
        the pod, and OpenVPN would fail to start with no device to open.
        """
        assert _volume(external_pki, "tun")
        assert _mount(external_pki, "tun")

    def test_paths_sit_under_the_read_only_secret_mount(self, external_pki):
        mount = _mount(external_pki, "pki-external")
        assert mount["readOnly"] is True
        assert _volume(external_pki, "pki-external")["secret"]["secretName"]
        paths = [
            value
            for name, value in external_pki["extraEnv"].items()
            if name.startswith("CULVERT_SECRETS_") and name.endswith("_PATH")
        ]
        assert len(paths) == 5
        assert all(path.startswith(mount["mountPath"] + "/") for path in paths)


class TestComposeFragment:
    """The generated fragment must describe a port something actually binds."""

    def test_vpn_port_is_published_as_udp(self):
        text = (REPO_ROOT / "deploy" / "compose" / "culvert.yaml").read_text(
            encoding="utf-8"
        )
        assert "1194:1194/udp" in text

    def test_gated_wireguard_port_is_not_published(self):
        """A default server opens no WireGuard port, so the fragment has none."""
        text = (REPO_ROOT / "deploy" / "compose" / "culvert.yaml").read_text(
            encoding="utf-8"
        )
        assert "51820" not in text


def _generator_module():
    """Load generate-deploy-artefacts.py, whose filename is not a module name."""
    import importlib.util

    path = REPO_ROOT / "scripts" / "generate-deploy-artefacts.py"
    spec = importlib.util.spec_from_file_location("generate_deploy_artefacts", path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCommittedArtefactsMatchTheGenerator:
    """The committed contract and fragment are generator output, byte for byte.

    Every other check in this file reads the committed files. A hand-edit, or a
    scalo bump that changes the generated shape, would pass all of them and be
    lost on the next regeneration. Fix a failure by running
    `python scripts/generate-deploy-artefacts.py` and committing the result.
    """

    @pytest.fixture
    def generated(self, tmp_path, monkeypatch):
        """Run the real generator into tmp_path, leaving the tree untouched."""
        module = _generator_module()
        contract_file = tmp_path / "deployment-contract.json"
        compose_file = tmp_path / "compose" / "culvert.yaml"
        monkeypatch.setattr(module, "CONTRACT_FILE", contract_file)
        monkeypatch.setattr(module, "COMPOSE_FILE", compose_file)
        module.main()
        return compose_file, contract_file

    def test_contract_matches_the_generator(self, generated):
        """release.helm assembles the published chart from the committed contract."""
        _, contract_file = generated
        committed = REPO_ROOT / "deploy" / "deployment-contract.json"
        assert committed.read_bytes() == contract_file.read_bytes()

    def test_compose_fragment_matches_the_generator(self, generated):
        compose_file, _ = generated
        committed = REPO_ROOT / "deploy" / "compose" / "culvert.yaml"
        assert committed.read_bytes() == compose_file.read_bytes()

    def test_no_chart_is_committed(self):
        """The chart is assembled from the contract at release, not kept here."""
        assert not (REPO_ROOT / "deploy" / "helm").exists()


def _secret_env_vars() -> list[tuple[str, str]]:
    """Each (group, env var) pair the contract's secret groups hand the pod."""
    return [
        (group.group_name, entry.env_var)
        for group in deployment_contract().secrets
        for entry in group.env_vars
    ]


class TestSecretEnvVarsAreRead:
    """A chart sets every env var a secret group names, so culvert must read each.

    One culvert does not read is a Secret key the deployer fills and the server
    ignores: OIDC then fails at runtime with a value that looks configured.
    """

    def test_the_contract_declares_secret_env_vars(self):
        assert _secret_env_vars(), "the contract declares no secret env vars"

    @pytest.mark.parametrize(
        ("group", "env_var"), _secret_env_vars(), ids=lambda value: str(value)
    )
    def test_config_reads_the_env_var(self, group, env_var, clean_env, monkeypatch):
        marker = f"marker-{env_var.lower()}"
        monkeypatch.setenv(env_var, marker)
        # A bool, so a failure never prints the config's values.
        read = marker in dataclasses.asdict(Config.from_settings()).values()
        # The message carries the env var and group names only, never a value.
        assert read, f"{env_var} (secret group {group}) is not read by Config"
