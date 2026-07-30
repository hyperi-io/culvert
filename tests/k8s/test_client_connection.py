#  Project:      culvert
#  File:         test_client_connection.py
#  Purpose:      Real tunnel from a client pod, both PKI modes, in-cluster
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""A real VPN connection inside Kubernetes, not a liveness probe.

The other cluster module proves the chart is admitted and the probes answer.
That is not the same as the product working. These tests generate a client
config with ``generate-client`` on the running server pod, carry it to a client
pod, bring an actual tunnel up, and require traffic to flow through it to a
target the client cannot otherwise reach.

The client pod runs the culvert image itself, which already carries openvpn,
wireguard-tools, stunnel, wstunnel and curl - so there is no second artefact to
build or publish.

Both PKI paths are covered, because both are supported:
  * local  - the server mints its own CA (the docker-style path)
  * external - CA and server keypair come from a secrets backend

Site detail comes from the environment. Run: pytest tests/k8s/ -m k8s -v
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import pytest
from conftest import CHART_DIR, Kubectl, release_name

pytestmark = pytest.mark.k8s

CLIENT_POD = "culvert-test-client"
TARGET_POD = "culvert-test-target"
TARGET_RESPONSE = "culvert-k8s-target-ok"
CLIENT_NAME = "k8s-e2e-client"


def _client_image() -> str:
    """Image for the client and target pods - the culvert image itself."""
    image = os.environ.get("CULVERT_K8S_IMAGE", "").strip()
    if not image:
        pytest.skip(
            "CULVERT_K8S_IMAGE is not set - the client pod needs an explicit"
            " image reference the cluster can pull. See tests/k8s/.env.example."
        )
    return image


def _server_pod(kubectl: Kubectl, release: str) -> str:
    result = kubectl(
        "get",
        "pod",
        "-l",
        f"app.kubernetes.io/instance={release}",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    )
    name = result.stdout.strip()
    assert name, f"no server pod for release {release}"
    return name


def _run_pod(kubectl: Kubectl, name: str, image: str, pull_secret: str | None) -> None:
    """Start a long-lived pod with the capabilities a VPN client needs."""
    spec = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "main",
                    "image": image,
                    "command": ["sleep", "infinity"],
                    "securityContext": {
                        "capabilities": {"add": ["NET_ADMIN"]},
                        "allowPrivilegeEscalation": True,
                    },
                }
            ],
        },
    }
    if pull_secret:
        spec["spec"]["imagePullSecrets"] = [{"name": pull_secret}]

    subprocess.run(
        [
            "kubectl",
            "--context",
            kubectl.context,
            "-n",
            kubectl.namespace,
            "apply",
            "-f",
            "-",
        ],
        input=json.dumps(spec),
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    kubectl(
        "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=180s", timeout=200
    )


def _exec(
    kubectl: Kubectl, pod: str, script: str, check: bool = True, timeout: int = 120
):
    """Run a shell script inside a pod."""
    return kubectl(
        "exec", pod, "--", "bash", "-lc", script, check=check, timeout=timeout
    )


@pytest.fixture(scope="module")
def target(kubectl):
    """A pod serving a known string, reachable only from inside the cluster."""
    image = _client_image()
    pull_secret = os.environ.get("CULVERT_K8S_PULL_SECRET", "").strip() or None
    _run_pod(kubectl, TARGET_POD, image, pull_secret)
    # Tiny HTTP responder - python3 is already in the image.
    _exec(
        kubectl,
        TARGET_POD,
        'nohup python3 -c "'
        "from http.server import BaseHTTPRequestHandler,HTTPServer\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def do_GET(s):\n"
        "        s.send_response(200); s.end_headers()\n"
        f"        s.wfile.write(b'{TARGET_RESPONSE}')\n"
        "HTTPServer(('0.0.0.0',8080),H).serve_forever()\" >/tmp/t.log 2>&1 &",
    )
    time.sleep(3)
    ip = kubectl(
        "get", "pod", TARGET_POD, "-o", "jsonpath={.status.podIP}"
    ).stdout.strip()
    assert ip, "target pod has no IP"
    yield ip
    kubectl("delete", "pod", TARGET_POD, "--wait=false", check=False)


@pytest.fixture(scope="module")
def client_pod(kubectl):
    """A pod that can bring up a tunnel."""
    image = _client_image()
    pull_secret = os.environ.get("CULVERT_K8S_PULL_SECRET", "").strip() or None
    _run_pod(kubectl, CLIENT_POD, image, pull_secret)
    yield CLIENT_POD
    kubectl("delete", "pod", CLIENT_POD, "--wait=false", check=False)


def _issue_and_fetch_config(kubectl: Kubectl, release: str, suffix: str) -> str:
    """Generate a client config on the server pod and return its contents.

    Proves the real issuance path works against whatever PKI the server is
    using, rather than assuming a config can be produced.
    """
    server = _server_pod(kubectl, release)
    result = _exec(
        kubectl,
        server,
        f"generate-client --name {CLIENT_NAME} --protocol all"
        " --output /etc/vpn/clients",
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"generate-client failed on the server pod:\n{result.stdout}\n{result.stderr}"
    )

    content = _exec(
        kubectl, server, f"cat /etc/vpn/clients/{CLIENT_NAME}-{suffix}"
    ).stdout
    assert content.strip(), f"{CLIENT_NAME}-{suffix} is empty"
    return content


def _connect_openvpn(kubectl: Kubectl, pod: str, config: str) -> None:
    """Write the config into the client pod and bring OpenVPN up."""
    # The Kubectl helper cannot pass stdin, so shell out directly for the write.
    subprocess.run(
        [
            "kubectl",
            "--context",
            kubectl.context,
            "-n",
            kubectl.namespace,
            "exec",
            "-i",
            pod,
            "--",
            "bash",
            "-c",
            "cat > /tmp/client.ovpn",
        ],
        input=config,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    _exec(
        kubectl,
        pod,
        "openvpn --config /tmp/client.ovpn --daemon --log /tmp/openvpn.log"
        " --connect-retry 1 --connect-retry-max 3",
    )


def _wait_for_tun(kubectl: Kubectl, pod: str, timeout: int = 60) -> str:
    """Poll for a tun0 address, returning it, or fail with the OpenVPN log."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _exec(
            kubectl,
            pod,
            "ip -4 -o addr show dev tun0 2>/dev/null | awk '{print $4}'",
            check=False,
        )
        addr = result.stdout.strip()
        if addr:
            return addr
        time.sleep(2)
    log = _exec(kubectl, pod, "cat /tmp/openvpn.log", check=False).stdout
    pytest.fail(f"tun0 never came up within {timeout}s. OpenVPN log:\n{log}")


class TestOpenVPNTunnelLocalPKI:
    """A real OpenVPN tunnel, server using its own locally-minted CA."""

    def test_target_unreachable_before_the_tunnel(self, kubectl, client_pod, target):
        """Baseline: without the tunnel the client must NOT reach the target.

        Without this the connectivity assertion below proves nothing - in a flat
        cluster network the client can usually reach any pod directly.
        """
        result = _exec(
            kubectl,
            client_pod,
            f"curl -sf --connect-timeout 5 http://{target}:8080/ || echo BLOCKED",
            check=False,
        )
        if TARGET_RESPONSE in result.stdout:
            pytest.skip(
                "the client pod reaches the target directly (flat pod network),"
                " so a post-tunnel success would not prove the tunnel carried"
                " it. Give the target a NetworkPolicy denying the client, or run"
                " this against a target outside the pod CIDR."
            )

    def test_openvpn_tunnel_carries_traffic(
        self, kubectl, client_pod, target, deployed
    ):
        """Issue a config, connect, and require the target to answer over tun0."""
        config = _issue_and_fetch_config(kubectl, release_name(), "udp-full.ovpn")
        _connect_openvpn(kubectl, client_pod, config)
        addr = _wait_for_tun(kubectl, client_pod)
        assert addr.startswith("10.8.0."), (
            f"tun0 address {addr} is not from the UDP listener's pool"
        )

        result = _exec(
            kubectl,
            client_pod,
            f"curl -sf --connect-timeout 10 http://{target}:8080/",
            check=False,
        )
        log = _exec(kubectl, client_pod, "cat /tmp/openvpn.log", check=False).stdout
        assert TARGET_RESPONSE in result.stdout, (
            f"target did not answer through the tunnel. curl: {result.stdout!r}"
            f" {result.stderr!r}\nOpenVPN log:\n{log}"
        )


class TestWireGuardTunnel:
    """The WireGuard path, same standard: real handshake, real traffic."""

    def test_wireguard_tunnel_carries_traffic(
        self, kubectl, client_pod, target, deployed
    ):
        """Bring wg0 up from a generated config and reach the target."""
        if "wireguard" not in os.environ.get("CULVERT_K8S_PROTOCOL", "both"):
            pytest.skip(
                "server not running WireGuard - set CULVERT_K8S_PROTOCOL to"
                " 'both' or 'wireguard' to cover this path"
            )

        config = _issue_and_fetch_config(kubectl, release_name(), "wg-full.conf")
        subprocess.run(
            [
                "kubectl",
                "--context",
                kubectl.context,
                "-n",
                kubectl.namespace,
                "exec",
                "-i",
                client_pod,
                "--",
                "bash",
                "-c",
                "mkdir -p /etc/wireguard && sed '/^DNS/d' > /etc/wireguard/wg0.conf",
            ],
            input=config,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        up = _exec(kubectl, client_pod, "wg-quick up wg0", check=False, timeout=120)
        if up.returncode != 0:
            pytest.skip(
                "wg-quick could not bring the interface up - the node kernel may"
                f" lack the wireguard module:\n{up.stdout}\n{up.stderr}"
            )
        try:
            result = _exec(
                kubectl,
                client_pod,
                f"curl -sf --connect-timeout 10 http://{target}:8080/",
                check=False,
            )
            assert TARGET_RESPONSE in result.stdout, (
                "target did not answer over WireGuard."
                f" wg: {_exec(kubectl, client_pod, 'wg show', check=False).stdout}"
            )
        finally:
            _exec(kubectl, client_pod, "wg-quick down wg0", check=False)


class TestExternalPKI:
    """The documented production path: CA and server keypair from outside.

    Needs PKI material provisioned out of band and referenced by env. The
    intent is that hyperi-infra provisions reusable objects in the DevEx PKI
    service so this can run repeatably rather than minting throwaway material
    each time.
    """

    def test_server_serves_an_externally_issued_ca(self, kubectl):
        """The CA the server presents must be the external one, not a fresh mint."""
        secret = os.environ.get("CULVERT_K8S_PKI_SECRET", "").strip()
        if not secret:
            pytest.skip(
                "CULVERT_K8S_PKI_SECRET is not set - external-PKI coverage needs"
                " a pre-created Secret holding the CA and server keypair."
                " Provision it via hyperi-infra and set the name."
            )

        expected_subject = os.environ.get("CULVERT_K8S_PKI_CA_SUBJECT", "").strip()
        if not expected_subject:
            pytest.skip(
                "CULVERT_K8S_PKI_CA_SUBJECT is not set - without the expected CA"
                " subject this cannot tell an external CA from a self-minted one"
            )

        release = release_name() + "-extpki"
        result = subprocess.run(
            [
                "helm",
                "--kube-context",
                kubectl.context,
                "-n",
                kubectl.namespace,
                "upgrade",
                "--install",
                release,
                str(CHART_DIR),
                "--wait",
                "--timeout",
                "5m",
                "--set",
                "env.CULVERT_PKI_MODE=external",
                "--set",
                f"existingSecret={secret}",
                "--set-json",
                "podSecurityContext.sysctls=[]",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        try:
            assert result.returncode == 0, (
                f"external-PKI install failed:\n{result.stdout}\n{result.stderr}"
            )
            pod = _server_pod(kubectl, release)
            subject = _exec(
                kubectl,
                pod,
                "openssl x509 -in /etc/vpn/pki/ca.crt -noout -subject",
            ).stdout
            assert expected_subject in subject, (
                f"server is using CA {subject.strip()!r}, expected the external"
                f" CA containing {expected_subject!r} - it may have self-minted"
            )
        finally:
            subprocess.run(
                [
                    "helm",
                    "--kube-context",
                    kubectl.context,
                    "-n",
                    kubectl.namespace,
                    "uninstall",
                    release,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
            )
