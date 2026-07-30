#  Project:      culvert
#  File:         test_loadbalancer.py
#  Purpose:      Prove culvert works behind a LoadBalancer Service
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Culvert behind a LoadBalancer, using the shipped k8s-scale starter values.

This is the deploy shape the chart is opinionated about
(``deploy/helm/culvert/values-k8s-scale.yaml``): LoadBalancer Service, HPA,
stdout logging. Two things here are worth more than "the Service got an
address":

- the starter ships FAIL-CLOSED, with an invalid ``loadBalancerSourceRanges``
  placeholder, so an unrestricted LB cannot be created by accident. The first
  test proves that guard actually bites.
- a VPN flow must stay pinned to the pod that accepted it. The starter enables
  an HPA with more than one replica, so the affinity behaviour is a real risk
  and is asserted rather than assumed.

Site detail comes from the environment. Run: pytest tests/k8s/ -m k8s -v
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest
from conftest import CHART_DIR, release_name
from conftest import helm as _helm

pytestmark = pytest.mark.k8s

RELEASE = release_name() + "-lb"
SCALE_VALUES = CHART_DIR / "values-k8s-scale.yaml"


def _require_lb_config() -> tuple[str, str | None]:
    """Source ranges and optional pinned address, or skip."""
    ranges = os.environ.get("CULVERT_K8S_LB_SOURCE_RANGES", "").strip()
    if not ranges:
        pytest.skip(
            "CULVERT_K8S_LB_SOURCE_RANGES is not set - LoadBalancer tests need"
            " the CIDRs allowed to reach the LB. See tests/k8s/.env.example."
        )
    return ranges, os.environ.get("CULVERT_K8S_LB_IP", "").strip() or None


class TestStarterShipsFailClosed:
    """The opinionated LB values must not create an open LB by accident."""

    def test_unreplaced_placeholder_is_rejected(self, kubectl, helm_values):
        """Installing the starter untouched must FAIL, not expose :9090.

        The starter sets loadBalancerSourceRanges to an invalid placeholder
        precisely so this install cannot succeed. If it ever does, the guard has
        been softened and an unauthenticated health/metrics endpoint is one
        `helm install` away from a public address.
        """
        _require_lb_config()
        result = _helm(
            "upgrade",
            "--install",
            RELEASE + "-guard",
            str(CHART_DIR),
            "-f",
            str(SCALE_VALUES),
            "--wait",
            "--timeout",
            "90s",
            *helm_values,
            context=kubectl.context,
            namespace=kubectl.namespace,
            check=False,
        )
        _helm(
            "uninstall",
            RELEASE + "-guard",
            context=kubectl.context,
            namespace=kubectl.namespace,
            check=False,
        )
        assert result.returncode != 0, (
            "the k8s-scale starter installed with its placeholder source range"
            " still in place - the fail-closed guard is not working"
        )


@pytest.fixture(scope="module")
def lb_deployed(kubectl, helm_values):
    """Install the scale starter with real source ranges, yield, tear down."""
    ranges, pinned_ip = _require_lb_config()
    context, namespace = kubectl.context, kubectl.namespace

    subprocess.run(
        ["kubectl", "--context", context, "create", "namespace", namespace],
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(
        [
            "kubectl",
            "--context",
            context,
            "label",
            "namespace",
            namespace,
            "pod-security.kubernetes.io/enforce=privileged",
            "--overwrite",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    args = [
        "--set-json",
        f"service.loadBalancerSourceRanges={json.dumps(ranges.split(','))}",
    ]
    if pinned_ip:
        # Pin the address so a test cannot claim one something else wants.
        args += ["--set", f"service.loadBalancerIP={pinned_ip}"]

    result = _helm(
        "upgrade",
        "--install",
        RELEASE,
        str(CHART_DIR),
        "-f",
        str(SCALE_VALUES),
        "--wait",
        "--timeout",
        "5m",
        *helm_values,
        *args,
        context=context,
        namespace=namespace,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            "LoadBalancer install failed.\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    yield kubectl

    _helm("uninstall", RELEASE, context=context, namespace=namespace, check=False)


class TestLoadBalancerService:
    """The Service must come up restricted, and carry the VPN port as UDP."""

    def test_service_gets_an_external_address(self, lb_deployed):
        """Without an address there is nothing for a client to dial."""
        result = lb_deployed(
            "get",
            "svc",
            RELEASE,
            "-o",
            "jsonpath={.status.loadBalancer.ingress[0].ip}",
        )
        assert result.stdout.strip(), (
            "the LoadBalancer Service never got an external address - is a"
            " controller (MetalLB or a cloud provider) present?"
        )

    def test_source_ranges_are_applied(self, lb_deployed):
        """An LB with no source restriction exposes :9090 unauthenticated."""
        result = lb_deployed(
            "get", "svc", RELEASE, "-o", "jsonpath={.spec.loadBalancerSourceRanges}"
        )
        applied = result.stdout.strip()
        assert applied and applied != "[]", (
            "loadBalancerSourceRanges is empty on the live Service - the"
            " observability port is reachable from anywhere the LB is"
        )
        assert "REPLACE-ME" not in applied, (
            f"the placeholder reached the live Service: {applied}"
        )

    def test_vpn_port_is_published_as_udp(self, lb_deployed):
        """OpenVPN's default listener is UDP; TCP here would silently not work."""
        result = lb_deployed("get", "svc", RELEASE, "-o", "json")
        ports = json.loads(result.stdout)["spec"]["ports"]
        udp = [p for p in ports if p.get("protocol") == "UDP" and p["port"] == 1194]
        assert udp, f"no UDP 1194 port on the Service: {json.dumps(ports, indent=2)}"

    def test_replicas_are_ready_behind_the_lb(self, lb_deployed):
        """The starter runs more than one replica - all must be serving."""
        result = lb_deployed(
            "get",
            "deploy",
            RELEASE,
            "-o",
            "jsonpath={.status.readyReplicas}/{.spec.replicas}",
        )
        ready, _, desired = result.stdout.strip().partition("/")
        assert ready and ready == desired, (
            f"only {ready or 0} of {desired} replicas are Ready behind the LB"
        )


class TestConnectionAffinity:
    """A VPN flow must stay pinned to one pod for its whole life."""

    def test_service_does_not_round_robin_packets(self, lb_deployed):
        """Per-packet balancing across pods breaks every tunnel.

        State is per-pod - client IP allocation, TLS session, WireGuard peer
        table. With more than one replica the Service must steer a flow
        consistently, which means either sessionAffinity ClientIP or
        externalTrafficPolicy Local. Neither being set on a multi-replica LB is
        a real misconfiguration, so it fails here rather than in production.
        """
        result = lb_deployed("get", "svc", RELEASE, "-o", "json")
        spec = json.loads(result.stdout)["spec"]

        replicas = lb_deployed(
            "get", "deploy", RELEASE, "-o", "jsonpath={.spec.replicas}"
        ).stdout.strip()
        if replicas in ("", "0", "1"):
            pytest.skip(f"only {replicas or 0} replica(s) - affinity is moot")

        affinity = spec.get("sessionAffinity", "None")
        policy = spec.get("externalTrafficPolicy", "Cluster")
        assert affinity == "ClientIP" or policy == "Local", (
            f"{replicas} replicas behind a LoadBalancer with"
            f" sessionAffinity={affinity} and externalTrafficPolicy={policy}."
            " Neither pins a flow to a pod, so tunnels will break when traffic"
            " lands on the wrong replica."
        )
