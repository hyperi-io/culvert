#  Project:      culvert
#  File:         test_client_lifecycle.py
#  Purpose:      Tests that revoke-client removes what generate-client wrote
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""generate-client then revoke-client, end to end, with the clients volume listed.

Both scripts run their real main() against one PKI and one clients directory
under tmp_path. Certificates are pre-issued and Easy-RSA is the conftest
stand-in, because neither Easy-RSA nor a WireGuard interface is on a CI runner.
"""

import importlib.util
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
SERVER_CN = "vpn.example.test"
TC_KEY = (
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"
    "dGxzLWNyeXB0LXYyIHRlc3Qga2V5\n"
    "-----END OpenVPN tls-crypt-v2 client key-----\n"
)
ALICE_KEY = "AliceSlot1PublicKey000000000000000000000000="
LAPTOP_KEY = "LaptopSlot1PublicKey00000000000000000000000="
PROXY_KEY = "ProxySlot1PublicKey000000000000000000000000="


def _load(filename: str, module_name: str):
    """Load a script whose filename is not a valid module name."""
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None, f"cannot load {filename}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def stack(tmp_path, issue_cert, easyrsa, clean_env, monkeypatch):
    """Both scripts, sharing one PKI, one clients directory and one wg0.conf."""
    import lib.config

    pki = tmp_path / "pki"
    for sub in ("issued", "private", "reqs", "wireguard"):
        (pki / sub).mkdir(parents=True)
    ca = issue_cert("culvert-test-ca", is_ca=True)
    (pki / "ca.crt").write_bytes(ca.cert_pem)
    (pki / "wireguard" / "server_private.key").write_text("ServerPrivate=\n")
    (pki / "wireguard" / "server_public.key").write_text(
        "ServerPublicKey0000000000000000000000000000=\n"
    )
    clients = tmp_path / "clients"
    wg_conf = tmp_path / "server" / "wg0.conf"
    wg_conf.parent.mkdir()

    monkeypatch.setenv("CULVERT_SERVER_CN", SERVER_CN)
    monkeypatch.setenv("OUTPUT_DIR", str(clients))
    real_from_settings = lib.config.Config.from_settings

    def from_settings(*args, **kwargs):
        cfg = real_from_settings(*args, **kwargs)
        cfg.pki_dir = pki
        cfg.wg_conf = wg_conf
        return cfg

    monkeypatch.setattr(lib.config.Config, "from_settings", staticmethod(from_settings))

    generate = _load("generate-client.py", "generate_client_lifecycle")
    revoke = _load("revoke-client.py", "revoke_client_lifecycle")
    monkeypatch.setattr(revoke, "EASYRSA_DIR", easyrsa)
    monkeypatch.setattr(revoke, "_wg_interface_up", lambda: False)

    def issue(name: str) -> None:
        client = issue_cert(name, issuer=ca)
        (pki / "issued" / f"{name}.crt").write_bytes(client.cert_pem)
        (pki / "private" / f"{name}.key").write_bytes(client.key_pem)
        (pki / "private" / f"{name}-tc.key").write_text(TC_KEY, encoding="utf-8")

    def run(module, prog: str, *args: str) -> None:
        monkeypatch.setattr(sys, "argv", [prog, *args])
        module.main()

    return SimpleNamespace(
        pki=pki,
        clients=clients,
        wg_conf=wg_conf,
        issue=issue,
        generate=lambda *args: run(generate, "generate-client", *args),
        revoke=lambda *args: run(revoke, "revoke-client", *args),
    )


def _issue_both_protocols(stack, name: str, pubkey: str, *extra: str) -> None:
    stack.issue(name)
    stack.generate("--protocol", "openvpn", "--config-only", "--name", name, *extra)
    stack.generate("--protocol", "wireguard", "--name", name, "--pubkey", pubkey)


def _volume(stack) -> list[str]:
    return sorted(path.name for path in stack.clients.iterdir())


class TestRevokeRemovesEverything:
    """Every file generate-client wrote for the client goes, and nobody else's."""

    def test_full_revocation_leaves_only_the_other_clients_files(self, stack):
        _issue_both_protocols(stack, "alice-laptop", LAPTOP_KEY)
        laptop = _volume(stack)
        _issue_both_protocols(
            stack, "alice", ALICE_KEY, "--proxy", "proxy.corp.example:8080"
        )

        stack.revoke("alice")

        assert _volume(stack) == laptop

    def test_wireguard_revocation_rebuilds_the_zip_without_its_configs(self, stack):
        _issue_both_protocols(stack, "alice", ALICE_KEY)

        stack.revoke("--protocol", "wireguard", "alice")

        assert not any(name.startswith("alice-wg") for name in _volume(stack))
        with zipfile.ZipFile(stack.clients / "alice.zip") as zf:
            names = zf.namelist()
        assert "alice-udp-split.ovpn" in names
        assert not any(name.startswith("alice-wg") for name in names)

    def test_openvpn_revocation_rebuilds_the_zip_without_its_configs(self, stack):
        _issue_both_protocols(stack, "alice", ALICE_KEY)

        stack.revoke("--protocol", "openvpn", "alice")

        remaining = _volume(stack)
        assert not any(name.endswith((".ovpn", "stunnel.conf")) for name in remaining)
        with zipfile.ZipFile(stack.clients / "alice.zip") as zf:
            assert sorted(zf.namelist()) == [
                "alice-wg-full.conf",
                "alice-wg-split.conf",
            ]


class TestSharedStunnelName:
    """alice-proxy-stunnel.conf is alice's proxy config and alice-proxy's direct one."""

    def test_revoking_alice_keeps_it_while_alice_proxy_is_issued(self, stack):
        _issue_both_protocols(stack, "alice-proxy", PROXY_KEY)
        _issue_both_protocols(
            stack, "alice", ALICE_KEY, "--proxy", "proxy.corp.example:8080"
        )

        stack.revoke("alice")

        assert "alice-proxy-stunnel.conf" in _volume(stack)

    def test_revoking_alice_proxy_keeps_it_while_alice_uses_a_proxy(self, stack):
        _issue_both_protocols(
            stack, "alice", ALICE_KEY, "--proxy", "proxy.corp.example:8080"
        )
        _issue_both_protocols(stack, "alice-proxy", PROXY_KEY)

        stack.revoke("alice-proxy")

        assert "alice-proxy-stunnel.conf" in _volume(stack)
        assert "alice-proxy.zip" not in _volume(stack)
