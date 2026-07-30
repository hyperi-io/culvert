#  Project:      culvert
#  File:         test_chart_deploy.py
#  Purpose:      Install the Helm chart on a real cluster and prove it works
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Install the shipped Helm chart on a real cluster and exercise it.

`helm template` and kubeconform prove the chart is well-formed. They cannot
tell you the kubelet will accept the pod, that the probes answer, or that a
client outside the cluster gets a tunnel. That is what these do.

Every site-specific value comes from the environment (see conftest.py and
.env.example) so this file leaks nothing about any particular cluster.

Run: pytest tests/k8s/ -m k8s -v
Never runs in CI.
"""

from __future__ import annotations

import json
import time

import pytest
from conftest import ready_pod, release_name

pytestmark = pytest.mark.k8s

RELEASE = release_name()


def _pod_name(kubectl) -> str:
    """Name of the Ready culvert pod."""
    return ready_pod(kubectl, RELEASE)


class TestChartInstalls:
    """The pod the chart describes must actually be admitted and become Ready."""

    def test_pod_is_running_and_ready(self, deployed):
        """A rejected sysctl or missing device shows up here, not in a template."""
        result = deployed(
            "get",
            "pod",
            "-l",
            f"app.kubernetes.io/instance={RELEASE}",
            "-o",
            "json",
        )
        pods = json.loads(result.stdout)["items"]
        assert pods, "the release created no pods"

        pod = pods[0]
        assert pod["status"]["phase"] == "Running", (
            f"pod is {pod['status']['phase']}: {json.dumps(pod['status'], indent=2)}"
        )
        ready = [c for c in pod["status"].get("conditions", []) if c["type"] == "Ready"]
        assert ready and ready[0]["status"] == "True", (
            f"pod never became Ready: {json.dumps(pod['status'], indent=2)}"
        )

    def test_runs_as_root_with_net_admin(self, deployed):
        """The VPN data plane needs both; the chart substitutes the non-root floor."""
        result = deployed(
            "get",
            "pod",
            "-l",
            f"app.kubernetes.io/instance={RELEASE}",
            "-o",
            "jsonpath={.items[0].spec.containers[0].securityContext}",
        )
        sec = json.loads(result.stdout) if result.stdout.strip() else {}
        added = (sec.get("capabilities") or {}).get("add") or []
        assert "NET_ADMIN" in added, f"NET_ADMIN not granted: {sec}"
        # OpenVPN drops to user nobody once its sockets are bound and needs
        # these to do it. Without them it exits 1 and the chart never starts.
        for cap in ("SETPCAP", "SETGID", "SETUID"):
            assert cap in added, (
                f"{cap} not granted: {sec}. OpenVPN cannot complete its"
                " privilege drop without it and exits during startup."
            )
        assert sec.get("allowPrivilegeEscalation") is False, (
            f"allowPrivilegeEscalation should be false: {sec}"
        )
        assert sec.get("runAsNonRoot") is not True, (
            "runAsNonRoot must not be set - OpenVPN and wg-quick need root"
        )

    def test_ip_forwarding_is_on_in_the_pod(self, deployed):
        """Without this the server completes handshakes and forwards nothing.

        A container's /proc/sys is read-only however many capabilities it holds,
        so the entrypoint cannot set this and only the privileged init container
        can. The pod looks perfectly healthy either way - probes pass, clients
        connect - and then no traffic reaches anything.
        """
        pod = _pod_name(deployed)
        result = deployed("exec", pod, "--", "cat", "/proc/sys/net/ipv4/ip_forward")
        assert result.stdout.strip() == "1", (
            "net.ipv4.ip_forward is off in the pod network namespace - is"
            " ipForward.enabled set, and did the init container run?"
        )

    def test_service_account_token_not_mounted(self, deployed):
        """The VPN never calls the API, so the token should not be there."""
        result = deployed(
            "get",
            "pod",
            "-l",
            f"app.kubernetes.io/instance={RELEASE}",
            "-o",
            "jsonpath={.items[0].spec.automountServiceAccountToken}",
        )
        assert result.stdout.strip() == "false", (
            f"expected automountServiceAccountToken false, got {result.stdout!r}"
        )


class TestProbesOnCluster:
    """The probe surface, verified in-cluster rather than in a rendered template."""

    def test_livez_and_readyz_answer(self, deployed):
        """Both canonical paths must return 200 from inside the pod."""
        pod = _pod_name(deployed)
        for path in ("/livez", "/readyz"):
            result = deployed(
                "exec",
                pod,
                "--",
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://localhost:9090{path}",
            )
            assert result.stdout.strip() == "200", (
                f"{path} returned {result.stdout.strip()!r}, expected 200"
            )

    @pytest.mark.parametrize(
        "path", ["/healthz", "/health/live", "/health/ready", "/health/startup"]
    )
    def test_retired_probe_paths_are_gone(self, deployed, path):
        """A retired alias must 404 on the cluster too, not just in unit tests."""
        pod = _pod_name(deployed)
        result = deployed(
            "exec",
            pod,
            "--",
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            f"http://localhost:9090{path}",
        )
        assert result.stdout.strip() == "404", (
            f"{path} returned {result.stdout.strip()!r}, expected 404 -"
            " a chart probing a retired name would look healthy while wrong"
        )

    def test_kubelet_probes_report_healthy(self, deployed):
        """No probe restarts means the kubelet agrees with the paths we set."""
        result = deployed(
            "get",
            "pod",
            "-l",
            f"app.kubernetes.io/instance={RELEASE}",
            "-o",
            "jsonpath={.items[0].status.containerStatuses[0].restartCount}",
        )
        assert result.stdout.strip() == "0", (
            f"container restarted {result.stdout.strip()} time(s) - a failing"
            " liveness probe is the likely cause"
        )


class TestDrain:
    """SIGTERM must not hang, or a rollout stalls for the grace period."""

    def test_pod_terminates_promptly(self, deployed):
        """Delete the pod and confirm the replacement comes back Ready."""
        pod = _pod_name(deployed)
        started = time.monotonic()
        deployed("delete", "pod", pod, "--wait=true", timeout=180)
        elapsed = time.monotonic() - started

        grace = 30
        assert elapsed < grace, (
            f"pod took {elapsed:.0f}s to terminate (grace {grace}s) - SIGTERM"
            " handling is likely not draining cleanly"
        )

        deployed(
            "wait",
            "--for=condition=Ready",
            "pod",
            "-l",
            f"app.kubernetes.io/instance={RELEASE}",
            "--timeout=180s",
            timeout=200,
        )
