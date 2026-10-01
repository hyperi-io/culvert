#  Project:      culvert
#  File:         test_generate_client.py
#  Purpose:      Tests for generate-client's issued OpenVPN and WireGuard configs
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""generate-client, run end to end against a real PKI in a temporary directory.

The certificate is pre-issued, so every run uses --config-only: Easy-RSA is not
on a CI runner, and the part that differs between clients is the config text.
`openssl x509` is called for real to extract the certificate the configs embed.
"""

import importlib.util
import stat
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate-client.py"

SERVER_CN = "vpn.example.test"
CLIENT = "alice"
TC_KEY = (
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
    "dGxzLWNyeXB0LXYyIHRlc3Qga2V5\n"
    "-----END OpenVPN tls-crypt-v2 client key-----\n"
)
# Easy-RSA writes a human-readable dump above the PEM block of an issued cert.
CERT_TEXT_DUMP = "Certificate:\n    Data:\n        Version: 3 (0x2)\n"
PUBKEY_1 = "AliceSlot1PublicKey000000000000000000000000="
PUBKEY_2 = "AliceSlot2PublicKey000000000000000000000000="
SERVER_PUBLIC = "ServerPublicKey0000000000000000000000000000="
TWO_SLOTS = (
    "--protocol",
    "wireguard",
    "--name",
    CLIENT,
    "--pubkey",
    PUBKEY_1,
    "--pubkey",
    PUBKEY_2,
)


def _module():
    """Load generate-client.py, whose filename is not a valid module name."""
    spec = importlib.util.spec_from_file_location("generate_client_script", SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pki(tmp_path, issue_cert):
    """A PKI holding a CA, one issued client and a WireGuard server keypair."""
    pki_dir = tmp_path / "pki"
    for sub in ("issued", "private", "wireguard"):
        (pki_dir / sub).mkdir(parents=True)

    ca = issue_cert("culvert-test-ca", is_ca=True)
    client = issue_cert(CLIENT, issuer=ca)
    (pki_dir / "ca.crt").write_bytes(ca.cert_pem)
    (pki_dir / "issued" / f"{CLIENT}.crt").write_text(
        CERT_TEXT_DUMP + client.cert_pem.decode(), encoding="utf-8"
    )
    (pki_dir / "private" / f"{CLIENT}.key").write_bytes(client.key_pem)
    (pki_dir / "private" / f"{CLIENT}-tc.key").write_text(TC_KEY, encoding="utf-8")

    wg_dir = pki_dir / "wireguard"
    (wg_dir / "server_private.key").write_text("ServerPrivate=\n", encoding="utf-8")
    (wg_dir / "server_public.key").write_text(SERVER_PUBLIC + "\n", encoding="utf-8")
    return SimpleNamespace(
        dir=pki_dir,
        ca_cert_pem=ca.cert_pem.decode(),
        client_cert_pem=client.cert_pem.decode(),
    )


class Runner:
    """generate-client's main(), plus the paths a test inspects afterwards."""

    def __init__(self, module, out: Path, wg_conf: Path, monkeypatch) -> None:
        self.module = module
        self.out = out
        self.wg_conf = wg_conf
        self._monkeypatch = monkeypatch

    def __call__(self, *args: str) -> Path:
        argv = ["generate-client", "--output", str(self.out), *args]
        self._monkeypatch.setattr(sys, "argv", argv)
        self.module.main()
        return self.out


@pytest.fixture
def run(tmp_path, pki, clean_env, monkeypatch):
    """Call generate-client's main() with CLI args, PKI and outputs under tmp_path."""
    monkeypatch.setenv("CULVERT_SERVER_CN", SERVER_CN)
    module = _module()
    wg_conf = tmp_path / "server" / "wg0.conf"
    wg_conf.parent.mkdir()

    class TmpConfig(module.Config):
        def __init__(self):
            super().__init__()
            self.pki_dir = pki.dir
            self.wg_conf = wg_conf

    monkeypatch.setattr(module, "Config", TmpConfig)
    return Runner(module, tmp_path / "clients", wg_conf, monkeypatch)


class TestOpenVpnConfigs:
    """The six listener x tunnel-mode configs a client is issued."""

    def test_issues_one_config_per_listener_and_mode(self, run):
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        assert sorted(p.name for p in out.glob("*.ovpn")) == [
            f"{CLIENT}-{proto}-{mode}.ovpn"
            for proto in ("https", "tcp", "udp")
            for mode in ("full", "split")
        ]

    def test_configs_embed_the_client_material(self, run, pki):
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        text = (out / f"{CLIENT}-udp-split.ovpn").read_text(encoding="utf-8")

        assert f"<ca>\n{pki.ca_cert_pem}</ca>" in text
        assert f"<cert>\n{pki.client_cert_pem}</cert>" in text
        assert f"<tls-crypt-v2>\n{TC_KEY}</tls-crypt-v2>" in text
        assert "BEGIN PRIVATE KEY" in text
        assert f"verify-x509-name {SERVER_CN} name" in text

    def test_certificate_text_dump_is_not_embedded(self, run):
        """Only the PEM block goes in; the dump above it is not a certificate."""
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        text = (out / f"{CLIENT}-udp-split.ovpn").read_text(encoding="utf-8")
        assert "Certificate:" not in text

    def test_configs_are_private_to_the_owner(self, run):
        """Each config carries the client's private key."""
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        for path in out.glob("*.ovpn"):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name

    def test_each_listener_dials_its_own_remote(self, run):
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)

        def remote(name):
            text = (out / f"{CLIENT}-{name}-split.ovpn").read_text(encoding="utf-8")
            return [line for line in text.splitlines() if line.startswith("remote ")]

        assert remote("udp") == [f"remote {SERVER_CN} 1194 udp"]
        assert remote("tcp") == [f"remote {SERVER_CN} 1194 tcp"]
        # The HTTPS listener is reached through a local stunnel.
        assert remote("https") == ["remote 127.0.0.1 1195 tcp"]

    def test_split_carries_extra_routes_and_full_redirects(self, run):
        out = run(
            "--protocol",
            "openvpn",
            "--config-only",
            "--name",
            CLIENT,
            "--routes",
            "10.1.0.0/16, 192.168.5.0/24",
        )
        split = (out / f"{CLIENT}-udp-split.ovpn").read_text(encoding="utf-8")
        full = (out / f"{CLIENT}-udp-full.ovpn").read_text(encoding="utf-8")

        assert "route 10.1.0.0/16\n" in split
        assert "route 192.168.5.0/24\n" in split
        assert "redirect-gateway" not in split
        assert "redirect-gateway def1 bypass-dhcp" in full
        assert "route 10.1.0.0/16" not in full

    def test_https_listener_gets_a_tls_1_3_stunnel_config(self, run):
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        stunnel = (out / f"{CLIENT}-stunnel.conf").read_text(encoding="utf-8")

        assert "sslVersionMin = TLSv1.3" in stunnel
        assert f"connect = {SERVER_CN}:443" in stunnel
        assert f"checkHost = {SERVER_CN}" in stunnel

    def test_files_are_bundled_into_the_clients_zip(self, run):
        out = run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        with zipfile.ZipFile(out / f"{CLIENT}.zip") as zf:
            names = set(zf.namelist())
        assert f"{CLIENT}-udp-split.ovpn" in names
        assert f"{CLIENT}-stunnel.conf" in names


class TestProxyMode:
    """The proxy is stunnel's to speak to: OpenVPN's own remote is loopback."""

    def test_openvpn_config_has_no_http_proxy_directive(self, run):
        out = run(
            "--protocol",
            "openvpn",
            "--config-only",
            "--name",
            CLIENT,
            "--proxy",
            "proxy.corp.example:8080",
        )
        for mode in ("split", "full"):
            text = (out / f"{CLIENT}-proxy-{mode}.ovpn").read_text(encoding="utf-8")
            assert "http-proxy" not in text
            assert "remote 127.0.0.1 1195 tcp" in text
            assert "PROXY MODE" in text

    def test_stunnel_connects_through_the_proxy(self, run):
        out = run(
            "--protocol",
            "openvpn",
            "--config-only",
            "--name",
            CLIENT,
            "--proxy",
            "proxy.corp.example:8080",
        )
        stunnel = (out / f"{CLIENT}-proxy-stunnel.conf").read_text(encoding="utf-8")

        assert "connect = proxy.corp.example:8080" in stunnel
        assert "protocol = connect" in stunnel
        assert f"protocolHost = {SERVER_CN}:443" in stunnel
        assert "# protocolAuthentication = basic" in stunnel

    def test_proxy_auth_writes_live_placeholders(self, run):
        out = run(
            "--protocol",
            "openvpn",
            "--config-only",
            "--name",
            CLIENT,
            "--proxy",
            "proxy.corp.example:8080",
            "--proxy-auth",
        )
        stunnel = (out / f"{CLIENT}-proxy-stunnel.conf").read_text(encoding="utf-8")
        assert "\nprotocolAuthentication = basic\n" in stunnel
        assert "protocolUsername = CHANGE_ME" in stunnel

    def test_proxy_run_keeps_the_direct_stunnel_config(self, run):
        """Both are built from the same branch; a shared name lost the direct one."""
        out = run(
            "--protocol",
            "openvpn",
            "--config-only",
            "--name",
            CLIENT,
            "--proxy",
            "proxy.corp.example:8080",
        )
        direct = (out / f"{CLIENT}-stunnel.conf").read_text(encoding="utf-8")
        assert f"connect = {SERVER_CN}:443" in direct
        assert "protocol = connect" not in direct


class TestRefusals:
    """Each refusal exits non-zero before anything is written."""

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(("--name", "../ca"), id="path-traversal-name"),
            pytest.param(("--proxy", "not a proxy"), id="malformed-proxy"),
            pytest.param(
                ("--protocol", "openvpn", "--pubkey", PUBKEY_1),
                id="pubkey-without-wireguard",
            ),
            pytest.param(("--pubkey", "short="), id="malformed-pubkey"),
            pytest.param(("--pubkey", PUBKEY_1, "--pubkey", PUBKEY_1), id="dup-pubkey"),
        ],
    )
    def test_invalid_arguments_exit(self, run, tmp_path, args):
        with pytest.raises(SystemExit) as exc_info:
            run("--name", CLIENT, *args)
        assert exc_info.value.code == 1
        assert not (tmp_path / "clients").exists()

    def test_several_pubkeys_need_sharing_enabled(self, run, monkeypatch):
        monkeypatch.setenv("CULVERT_ALLOW_SHARED_CLIENTS", "false")
        with pytest.raises(SystemExit) as exc_info:
            run("--name", CLIENT, "--pubkey", PUBKEY_1, "--pubkey", PUBKEY_2)
        assert exc_info.value.code == 1

    def test_uninitialised_pki_exits(self, run, pki):
        (pki.dir / "ca.crt").unlink()
        with pytest.raises(SystemExit) as exc_info:
            run("--protocol", "openvpn", "--config-only", "--name", CLIENT)
        assert exc_info.value.code == 1

    def test_config_only_needs_an_existing_certificate(self, run):
        with pytest.raises(SystemExit) as exc_info:
            run("--protocol", "openvpn", "--config-only", "--name", "bob")
        assert exc_info.value.code == 1

    def test_existing_certificate_is_not_reissued(self, run, pki):
        """Re-issuing would orphan the old certificate without revoking it."""
        before = (pki.dir / "issued" / f"{CLIENT}.crt").read_bytes()
        with pytest.raises(SystemExit) as exc_info:
            run("--protocol", "openvpn", "--name", CLIENT)
        assert exc_info.value.code == 1
        assert (pki.dir / "issued" / f"{CLIENT}.crt").read_bytes() == before

    def test_unknown_listener_is_a_programming_error(self, run, tmp_path):
        cfg = run.module.Config()
        with pytest.raises(ValueError, match="Unknown protocol"):
            run.module.generate_ovpn_config(
                CLIENT, "split", tmp_path / "x.ovpn", "sctp", cfg
            )


class TestWireGuardClientSideKeys:
    """Supplied public keys: one device slot each, no private key embedded."""

    def test_issues_split_and_full_per_slot(self, run):
        out = run(*TWO_SLOTS)
        assert sorted(p.name for p in out.glob("*.conf")) == [
            f"{CLIENT}-wg-full.conf",
            f"{CLIENT}-wg-split.conf",
            f"{CLIENT}-wg2-full.conf",
            f"{CLIENT}-wg2-split.conf",
        ]

    def test_configs_carry_no_private_key_and_distinct_addresses(self, run):
        out = run(*TWO_SLOTS)
        first = (out / f"{CLIENT}-wg-split.conf").read_text(encoding="utf-8")
        second = (out / f"{CLIENT}-wg2-split.conf").read_text(encoding="utf-8")

        assert "PrivateKey = YOUR_PRIVATE_KEY_HERE" in first
        assert f"PublicKey = {SERVER_PUBLIC}" in first
        assert f"Endpoint = {SERVER_CN}:51820" in first
        assert "Address = 10.8.3.2/32" in first
        assert "Address = 10.8.3.3/32" in second

    def test_split_routes_only_the_tunnel_network(self, run):
        out = run("--protocol", "wireguard", "--name", CLIENT, "--pubkey", PUBKEY_1)
        split = (out / f"{CLIENT}-wg-split.conf").read_text(encoding="utf-8")
        full = (out / f"{CLIENT}-wg-full.conf").read_text(encoding="utf-8")
        assert "AllowedIPs = 10.8.3.0/24" in split
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in full

    def test_server_config_gains_a_peer_per_slot(self, run):
        """Issuing rewrites the config the running server reads."""
        run(*TWO_SLOTS)
        server = run.wg_conf.read_text(encoding="utf-8")
        assert server.count("[Peer]") == 2
        assert f"PublicKey = {PUBKEY_1}" in server
        assert f"PublicKey = {PUBKEY_2}" in server
        assert stat.S_IMODE(run.wg_conf.stat().st_mode) == 0o600

    def test_https_tunnel_variants_when_enabled(self, run, monkeypatch):
        monkeypatch.setenv("CULVERT_WG_HTTPS_TUNNEL_ENABLED", "true")
        out = run("--protocol", "wireguard", "--name", CLIENT, "--pubkey", PUBKEY_1)
        tunnelled = (out / f"{CLIENT}-wg-https-split.conf").read_text(encoding="utf-8")
        assert "Endpoint = 127.0.0.1:51820" in tunnelled
        assert f"wss://{SERVER_CN}:4443" in tunnelled
