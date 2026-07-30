#  Project:      culvert
#  File:         conftest.py
#  Purpose:      Cluster test configuration - all site detail comes from env
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Configuration for the Kubernetes chart tests.

These tests install the real Helm chart on a real cluster, so they need a
cluster to point at. Every site-specific value - context, addresses, hostnames,
image reference, pull secret - is read from the environment, never hardcoded,
so nothing about any particular cluster lands in this repository.

Put your values in ``tests/k8s/.env`` (gitignored) and they are picked up
automatically. ``tests/k8s/.env.example`` lists what is available.

Without configuration every test in this directory SKIPS with a message saying
what is missing, so a plain ``pytest`` run stays green for someone who has no
cluster. They never run in CI: the ``k8s`` marker is deselected there and the
tier is disabled in .hyperi-ci.yaml.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ENV_FILE = Path(__file__).parent / ".env"

# Namespace and release name are ours, not the site's, so they carry defaults.
DEFAULT_NAMESPACE = "culvert-test"
DEFAULT_RELEASE = "culvert-test"

CHART_DIR = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "culvert"


def _load_env_file() -> None:
    """Load tests/k8s/.env into the environment if present.

    Deliberately minimal - KEY=value lines, # comments, optional quotes. Real
    values live only in this untracked file.
    """
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_env_file()


def _require(name: str) -> str:
    """Return an env var's value, or skip the test explaining what is missing."""
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.skip(
            f"{name} is not set - cluster tests need a target."
            f" Copy tests/k8s/.env.example to tests/k8s/.env and fill it in."
        )
    return value


class Kubectl:
    """A kubectl runner bound to one context and namespace.

    Callable so tests read as ``kubectl("get", "pod")``, while still carrying
    the context and namespace the fixtures need for helm and namespace calls.
    """

    def __init__(self, context: str, namespace: str) -> None:
        self.context = context
        self.namespace = namespace

    def __call__(
        self, *args: str, check: bool = True, timeout: int = 120
    ) -> subprocess.CompletedProcess[str]:
        """Run kubectl with the bound context and namespace."""
        return subprocess.run(
            ["kubectl", "--context", self.context, "-n", self.namespace, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )


@pytest.fixture(scope="session")
def kubectl() -> Kubectl:
    """A kubectl runner bound to the configured context and namespace."""
    if not shutil.which("kubectl"):
        pytest.skip("kubectl is not on PATH")
    return Kubectl(
        context=_require("CULVERT_K8S_CONTEXT"),
        namespace=os.environ.get("CULVERT_K8S_NAMESPACE", DEFAULT_NAMESPACE),
    )


@pytest.fixture(scope="session")
def helm_values() -> list[str]:
    """Build the --set arguments for a chart install on the target cluster.

    Everything here is site-specific and therefore env-driven.
    """
    args = [
        "--set",
        f"env.CULVERT_SERVER_CN={_require('CULVERT_K8S_SERVER_CN')}",
    ]

    image = os.environ.get("CULVERT_K8S_IMAGE", "").strip()
    if image:
        repository, _, tag = image.rpartition(":")
        args += ["--set", f"image.repository={repository or image}"]
        if tag:
            args += ["--set", f"image.tag={tag}"]

    pull_secret = os.environ.get("CULVERT_K8S_PULL_SECRET", "").strip()
    if pull_secret:
        args += ["--set", f"imagePullSecrets[0].name={pull_secret}"]

    # The chart requests net.ipv4.ip_forward, an unsafe sysctl. A kubelet
    # without --allowed-unsafe-sysctls rejects the pod outright, so unless the
    # cluster is known to permit it, drop the request and let the entrypoint
    # set it at runtime - it holds NET_ADMIN and does so already.
    if os.environ.get("CULVERT_K8S_ALLOW_UNSAFE_SYSCTLS", "").lower() != "true":
        args += ["--set-json", "podSecurityContext.sysctls=[]"]

    protocol = os.environ.get("CULVERT_K8S_PROTOCOL", "").strip()
    if protocol:
        args += ["--set", f"env.CULVERT_PROTOCOL={protocol}"]

    return args


def helm(*args: str, context: str, namespace: str, check: bool = True, timeout=600):
    """Run helm against a given context and namespace."""
    return subprocess.run(
        ["helm", "--kube-context", context, "-n", namespace, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def release_name() -> str:
    """Helm release name for the chart under test."""
    return os.environ.get("CULVERT_K8S_RELEASE", DEFAULT_RELEASE)


@pytest.fixture(scope="session")
def deployed(kubectl, helm_values):
    """Install the chart, yield the kubectl runner, then tear it all down.

    Session-scoped and defined here rather than in a test module so every
    cluster module shares one installed release - the connection tests need the
    same server the deploy tests assert on.
    """
    context, namespace = kubectl.context, kubectl.namespace
    release = release_name()

    subprocess.run(
        ["kubectl", "--context", context, "create", "namespace", namespace],
        capture_output=True,
        text=True,
        check=False,
    )
    # The VPN pod needs NET_ADMIN, /dev/net/tun and root, which a restricted
    # PodSecurity namespace rejects outright.
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

    result = helm(
        "upgrade",
        "--install",
        release,
        str(CHART_DIR),
        "--wait",
        "--timeout",
        "5m",
        *helm_values,
        context=context,
        namespace=namespace,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            "helm install failed. This is the interesting failure - the chart"
            " renders and validates offline, so a failure here is the cluster"
            f" rejecting it.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    yield kubectl

    helm("uninstall", release, context=context, namespace=namespace, check=False)
    subprocess.run(
        [
            "kubectl",
            "--context",
            context,
            "delete",
            "namespace",
            namespace,
            "--wait=false",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
