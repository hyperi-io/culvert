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
from conftest import CHART_DIR, Kubectl, ready_pod, release_name

pytestmark = pytest.mark.k8s

CLIENT_POD = "culvert-test-k8s-client"
TARGET_POD = "culvert-test-k8s-target"
TARGET_RESPONSE = "culvert-test-k8s-target-ok"
CLIENT_NAME = "culvert-test-k8s-client"
TARGET_LABEL = "culvert-test-k8s-target"
NETPOL_NAME = "culvert-test-k8s-target-isolation"

# Label key used to select the target pod. Every object this tier creates
# carries it, which is also how the sweep in conftest finds strays.
TIER_LABEL_KEY = "culvert-test-tier"

# Pod networks are flat by default, so the client could reach the target without
# any tunnel and every connectivity assertion below would prove nothing. This
# policy admits the culvert pod only. Traffic that arrives through the tunnel is
# masqueraded to the server's pod IP, so it passes; the client's own packets do
# not.
_TARGET_NETWORK_POLICY = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": NETPOL_NAME},
    "spec": {
        "podSelector": {"matchLabels": {TIER_LABEL_KEY: TARGET_LABEL}},
        "policyTypes": ["Ingress"],
        "ingress": [
            {
                "from": [
                    {
                        "podSelector": {
                            "matchLabels": {"app.kubernetes.io/name": "culvert"}
                        }
                    }
                ]
            }
        ],
    },
}


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
    return ready_pod(kubectl, release)


def _run_pod(
    kubectl: Kubectl,
    name: str,
    image: str,
    pull_secret: str | None,
    labels: dict[str, str] | None = None,
) -> None:
    """Start a long-lived pod with the capabilities a VPN client needs."""
    spec = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": labels or {}},
        "spec": {
            "restartPolicy": "Never",
            # A VPN client opens a tun device just as the server does, so it
            # needs the same host device passed through - without it OpenVPN
            # completes the whole handshake and then fails to create tun0.
            "volumes": [
                {
                    "name": "tun",
                    "hostPath": {"path": "/dev/net/tun", "type": "CharDevice"},
                }
            ],
            # wg-quick routes an AllowedIPs=0.0.0.0/0 tunnel with an fwmark and
            # a policy rule, which needs net.ipv4.conf.all.src_valid_mark=1 or
            # strict rp_filter drops every encrypted packet coming back. It sets
            # that sysctl itself and the write fails silently in a container
            # (read-only /proc/sys), leaving a tunnel that handshakes and then
            # carries nothing. Only a privileged container can set it.
            "initContainers": [
                {
                    "name": "sysctl",
                    "image": image,
                    "command": [
                        "sysctl",
                        "-w",
                        "net.ipv4.conf.all.src_valid_mark=1",
                    ],
                    "securityContext": {"privileged": True},
                }
            ],
            "containers": [
                {
                    "name": "main",
                    "image": image,
                    "command": ["sleep", "infinity"],
                    "volumeMounts": [{"name": "tun", "mountPath": "/dev/net/tun"}],
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
        encoding="utf-8",
        errors="replace",
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


def _apply(kubectl: Kubectl, manifest: dict) -> subprocess.CompletedProcess[str]:
    """Apply a manifest given as a dict."""
    return subprocess.run(
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
        input=json.dumps(manifest),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=120,
    )


@pytest.fixture(scope="module")
def target(kubectl):
    """A pod serving a known string, reachable only through the tunnel."""
    image = _client_image()
    pull_secret = os.environ.get("CULVERT_K8S_PULL_SECRET", "").strip() or None
    _apply(kubectl, _TARGET_NETWORK_POLICY)
    _run_pod(
        kubectl,
        TARGET_POD,
        image,
        pull_secret,
        labels={TIER_LABEL_KEY: TARGET_LABEL},
    )
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
    kubectl("delete", "networkpolicy", NETPOL_NAME, "--wait=false", check=False)


@pytest.fixture(scope="module")
def client_pod(kubectl):
    """A pod that can bring up a tunnel."""
    image = _client_image()
    pull_secret = os.environ.get("CULVERT_K8S_PULL_SECRET", "").strip() or None
    _run_pod(kubectl, CLIENT_POD, image, pull_secret)
    yield CLIENT_POD
    kubectl("delete", "pod", CLIENT_POD, "--wait=false", check=False)


def _issue_and_fetch_config(
    kubectl: Kubectl, release: str, suffix: str, dial: str | None = None
) -> str:
    """Generate a client config on the server pod and return its contents.

    Proves the real issuance path works against whatever PKI the server is
    using, rather than assuming a config can be produced. ``dial`` points the
    finished config at a different release's Service, which is how a config
    issued once is used against a second server sharing the same PKI.
    """
    server = _server_pod(kubectl, release)
    issue = (
        f"generate-client --name {CLIENT_NAME} --protocol all --output /etc/vpn/clients"
    )
    result = _exec(kubectl, server, issue, check=False, timeout=300)
    if result.returncode != 0:
        # A certificate for this name already exists, either from an earlier test
        # or from a sibling server sharing the CA. Re-cut the configs against it
        # rather than revoking and reissuing.
        result = _exec(
            kubectl, server, f"{issue} --config-only", check=False, timeout=300
        )
    assert result.returncode == 0, (
        f"generate-client failed on the server pod:\n{result.stdout}\n{result.stderr}"
    )

    content = _exec(
        kubectl, server, f"cat /etc/vpn/clients/{CLIENT_NAME}-{suffix}"
    ).stdout
    assert content.strip(), f"{CLIENT_NAME}-{suffix} is empty"
    return _point_at_service(kubectl, dial or release, content)


def _service_dns(kubectl: Kubectl, release: str) -> str:
    """In-cluster DNS name of the release's Service."""
    name = kubectl(
        "get",
        "svc",
        "-l",
        f"app.kubernetes.io/instance={release}",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ).stdout.strip()
    assert name, f"no Service for release {release}"
    return f"{name}.{kubectl.namespace}.svc.cluster.local"


def _point_at_service(kubectl: Kubectl, release: str, config: str) -> str:
    """Redirect a client config at the in-cluster Service.

    The config the server issues names CULVERT_SERVER_CN, which is the public
    DNS name clients dial and does not resolve from inside the cluster. Swapping
    the destination for the Service name is what an operator does when the same
    server answers on more than one address, and it means the connection is made
    through the Service rather than straight at a pod IP.
    """
    dns = _service_dns(kubectl, release)
    lines = []
    for line in config.splitlines():
        stripped = line.strip()
        if stripped.startswith("remote "):
            parts = stripped.split()
            lines.append(" ".join(["remote", dns, *parts[2:]]))
        elif stripped.startswith("Endpoint"):
            _, _, value = stripped.partition("=")
            port = value.strip().rsplit(":", 1)[-1]
            lines.append(f"Endpoint = {dns}:{port}")
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"


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
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=60,
    )
    _exec(
        kubectl,
        pod,
        "openvpn --config /tmp/client.ovpn --daemon --log /tmp/openvpn.log"
        " --connect-retry 1 --connect-retry-max 3",
    )


def _write_wireguard_config(kubectl: Kubectl, pod: str, config: str) -> None:
    """Install a generated WireGuard config where wg-quick expects it.

    The DNS line goes: wg-quick shells out to resolvconf for it and the image
    has no resolvconf. Everything else is used as issued.
    """
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
            "mkdir -p /etc/wireguard && sed '/^DNS/d' > /etc/wireguard/wg0.conf",
        ],
        input=config,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=60,
    )


def _assert_tunnel_mode(
    kubectl: Kubectl, pod: str, iface: str, mode: str, target: str
) -> None:
    """Check the tunnel routes the way the requested mode says it should.

    Without this the two modes are indistinguishable: a split config that
    accidentally pulled a default route down would still reach the target and
    still pass, and so would a full config that only routed the pushed prefix.
    """
    to_target = _exec(kubectl, pod, f"ip route get {target}", check=False).stdout
    assert f"dev {iface}" in to_target, (
        f"{mode} tunnel does not route the target through {iface}:\n{to_target}"
    )

    # 1.1.1.1 stands in for "anywhere else". Nothing is sent to it.
    elsewhere = _exec(kubectl, pod, "ip route get 1.1.1.1", check=False).stdout
    if mode == "full":
        assert f"dev {iface}" in elsewhere, (
            "full tunnel is not carrying the default route - traffic outside the"
            f" pushed prefixes still leaves directly:\n{elsewhere}"
        )
    else:
        assert f"dev {iface}" not in elsewhere, (
            "split tunnel has captured the default route, so it is behaving as a"
            f" full tunnel and this test is not covering split at all:\n{elsewhere}"
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

        Without this the connectivity assertion below proves nothing - a flat
        pod network lets the client reach any pod directly, so the target
        fixture puts a NetworkPolicy in front of it that admits only the culvert
        pod. This asserts that policy is actually in force.
        """
        result = _exec(
            kubectl,
            client_pod,
            f"curl -sf --connect-timeout 5 http://{target}:8080/ || echo BLOCKED",
            check=False,
        )
        assert TARGET_RESPONSE not in result.stdout, (
            "the client pod reached the target WITHOUT the tunnel, so the"
            f" NetworkPolicy {NETPOL_NAME} is not being enforced. Every"
            " connectivity assertion in this module would pass vacuously."
            " Does this cluster's CNI implement NetworkPolicy?"
        )

    @pytest.mark.parametrize("mode", ["split", "full"])
    def test_openvpn_tunnel_carries_traffic(
        self, kubectl, client_pod, target, deployed, mode
    ):
        """Issue a config, connect, and require the target to answer over tun0.

        Both tunnel modes, because they route by different means and only one of
        them was ever exercised here: full tunnel pulls a default route down
        (``redirect-gateway``), while split tunnel carries only the routes the
        server pushes. A bug in either is invisible from the other.
        """
        config = _issue_and_fetch_config(kubectl, release_name(), f"udp-{mode}.ovpn")
        _connect_openvpn(kubectl, client_pod, config)
        try:
            addr = _wait_for_tun(kubectl, client_pod)
            assert addr.startswith("10.8.0."), (
                f"tun0 address {addr} is not from the UDP listener's pool"
            )
            _assert_tunnel_mode(kubectl, client_pod, "tun0", mode, target)

            result = _exec(
                kubectl,
                client_pod,
                f"curl -sf --connect-timeout 10 http://{target}:8080/",
                check=False,
            )
            log = _exec(kubectl, client_pod, "cat /tmp/openvpn.log", check=False).stdout
            assert TARGET_RESPONSE in result.stdout, (
                f"target did not answer through the {mode} tunnel."
                f" curl: {result.stdout!r} {result.stderr!r}\nOpenVPN log:\n{log}"
            )
        finally:
            # The client pod is reused by every tunnel test here, so this
            # connection has to be gone before the next one comes up.
            _exec(kubectl, client_pod, "pkill openvpn", check=False)


class TestWireGuardTunnel:
    """The WireGuard path, same standard: real handshake, real traffic."""

    @pytest.mark.parametrize("mode", ["split", "full"])
    def test_wireguard_tunnel_carries_traffic(
        self, kubectl, client_pod, target, deployed, mode
    ):
        """Bring wg0 up from a generated config and reach the target.

        Both modes: the split config's AllowedIPs is built from the pushed
        routes plus the WireGuard subnet, the full config's is 0.0.0.0/0, and
        wg-quick routes the two completely differently - a plain route for split,
        an fwmark and a policy rule for full.
        """
        protocol = os.environ.get("CULVERT_K8S_PROTOCOL", "both").strip() or "both"
        if protocol not in ("both", "wireguard"):
            pytest.skip(
                f"server is running {protocol} - set CULVERT_K8S_PROTOCOL to"
                " 'both' or 'wireguard' to cover this path"
            )

        config = _issue_and_fetch_config(kubectl, release_name(), f"wg-{mode}.conf")
        _write_wireguard_config(kubectl, client_pod, config)
        up = _exec(kubectl, client_pod, "wg-quick up wg0", check=False, timeout=120)
        if up.returncode != 0:
            pytest.skip(
                "wg-quick could not bring the interface up - the node kernel may"
                f" lack the wireguard module:\n{up.stdout}\n{up.stderr}"
            )
        try:
            if mode == "full":
                # Only the full config routes by fwmark, and only that needs the
                # sysctl. Assert it, because without it the handshake still
                # succeeds and only the data path fails, which reads as a server
                # fault when it is not one.
                mark = _exec(
                    kubectl,
                    client_pod,
                    "cat /proc/sys/net/ipv4/conf/all/src_valid_mark",
                    check=False,
                ).stdout.strip()
                assert mark == "1", (
                    "net.ipv4.conf.all.src_valid_mark is not set in the client"
                    " pod, so rp_filter will drop the tunnel's return traffic and"
                    " this test would fail for a reason that has nothing to do"
                    " with the server"
                )
            _assert_tunnel_mode(kubectl, client_pod, "wg0", mode, target)

            result = _exec(
                kubectl,
                client_pod,
                f"curl -sf --connect-timeout 10 http://{target}:8080/",
                check=False,
            )
            assert TARGET_RESPONSE in result.stdout, (
                f"target did not answer over the {mode} WireGuard tunnel."
                f" wg: {_exec(kubectl, client_pod, 'wg show', check=False).stdout}"
            )
        finally:
            _exec(kubectl, client_pod, "wg-quick down wg0", check=False)


class TestExternalPKI:
    """The documented production path: CA and server keypair from outside.

    The material comes from the ``pki_secret`` fixture - a Secret provisioned out
    of band where one exists (CULVERT_K8S_PKI_SECRET), otherwise the identity the
    local-PKI server minted for itself, copied into a Secret. Either way this
    server is handed PKI it did not create, which is the thing under test, and a
    tunnel is brought up over it because a server that loads a CA and then
    refuses connections has not passed.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def extpki_release(cls, kubectl, pki_secret, helm_values):
        """A second release running entirely on the supplied PKI material.

        A classmethod because pytest 9.1 deprecates a class-scoped fixture
        written as an instance method: the fixture runs once per class while
        each test gets a fresh instance, so anything set on self would be
        invisible to the tests. This one only yields a value, but the warning
        is an error here and would otherwise take the whole class down.
        """
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
                *helm_values,
                "--set",
                f"pkiSecret={pki_secret}",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            pytest.fail(
                f"external-PKI install failed:\n{result.stdout}\n{result.stderr}"
            )
        yield release
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
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=300,
        )

    def test_server_loads_the_supplied_ca(self, kubectl, pki_secret, extpki_release):
        """The CA on disk must be the one from the Secret, not a fresh mint."""
        from_secret = kubectl(
            "get",
            "secret",
            pki_secret,
            "-o",
            "jsonpath={.data['ca\\.crt']}",
        ).stdout.strip()
        assert from_secret, f"{pki_secret} has no ca.crt key"

        pod = _server_pod(kubectl, extpki_release)
        on_disk = _exec(kubectl, pod, "base64 -w0 /etc/vpn/pki/ca.crt").stdout.strip()
        assert on_disk == from_secret, (
            "the server is not using the CA it was given - it has probably"
            " self-minted one instead, which is what external PKI mode exists"
            " to avoid"
        )

    def test_shared_tls_crypt_key_is_the_supplied_one(
        self, kubectl, pki_secret, extpki_release
    ):
        """A locally minted key here would break every sibling replica."""
        from_secret = kubectl(
            "get",
            "secret",
            pki_secret,
            "-o",
            "jsonpath={.data['tc\\.key']}",
        ).stdout.strip()
        assert from_secret, f"{pki_secret} has no tc.key key"

        pod = _server_pod(kubectl, extpki_release)
        on_disk = _exec(kubectl, pod, "base64 -w0 /etc/vpn/pki/tc.key").stdout.strip()
        assert on_disk == from_secret, (
            "the server minted its own tls-crypt-v2 key instead of using the"
            " shared one, so clients issued by a sibling replica would be"
            " rejected"
        )

    def test_tunnel_works_on_external_pki(
        self, kubectl, client_pod, target, deployed, extpki_release
    ):
        """Same bar as local PKI: a real tunnel carrying real traffic.

        The config is issued by the server that OWNS the CA and then dialled at
        the external-PKI server, which never had the CA key and cannot sign
        anything. That is the property multi-replica depends on: a client issued
        once is accepted by any server holding the same material.
        """
        config = _issue_and_fetch_config(
            kubectl, release_name(), "udp-full.ovpn", dial=extpki_release
        )
        _connect_openvpn(kubectl, client_pod, config)
        try:
            _wait_for_tun(kubectl, client_pod)
            result = _exec(
                kubectl,
                client_pod,
                f"curl -sf --connect-timeout 10 http://{target}:8080/",
                check=False,
            )
            log = _exec(kubectl, client_pod, "cat /tmp/openvpn.log", check=False).stdout
            assert TARGET_RESPONSE in result.stdout, (
                "target did not answer through an external-PKI tunnel."
                f" curl: {result.stdout!r}\nOpenVPN log:\n{log}"
            )
        finally:
            _exec(kubectl, client_pod, "pkill openvpn", check=False)
