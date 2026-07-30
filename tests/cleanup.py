#!/usr/bin/env python3
#  Project:      culvert
#  File:         cleanup.py
#  Purpose:      Remove test infrastructure left behind by an interrupted run
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Remove test infrastructure left behind by an interrupted run.

The docker and Kubernetes tiers sweep what they own before they build, so a
killed run cannot poison the next one. This is for the other case: you killed a
run and want the containers, volumes, networks, pods and Helm release gone NOW,
without waiting for the next run to do it.

    python3 tests/cleanup.py                 # every tier
    python3 tests/cleanup.py docker          # e2e compose stacks only
    python3 tests/cleanup.py integration     # BATS integration containers only
    python3 tests/cleanup.py k8s             # cluster objects only

The docker and k8s cleanups are the same code the test run uses, imported
rather than reimplemented, so they cannot drift from what the fixtures do.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

TESTS_DIR = Path(__file__).resolve().parent

# The BATS tier names containers directly rather than through compose, so it is
# swept by name prefix instead of by a compose project label.
INTEGRATION_PREFIX = "culvert-test-integration"


def _load(name: str, path: Path) -> ModuleType:
    """Import a module from a path under a given name.

    Both tiers keep their cleanup in a file called conftest.py, so they cannot
    both be imported as the top-level ``conftest``; each gets its own name here.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def clean_docker() -> None:
    """Tear down both compose stacks and remove anything named for the tier."""
    sys.path[:0] = [str(TESTS_DIR), str(TESTS_DIR / "e2e")]
    e2e = _load("culvert_e2e_conftest", TESTS_DIR / "e2e" / "conftest.py")
    e2e.tidy_all()
    print("docker: compose stacks down, tier-named containers/volumes/networks removed")


def clean_integration() -> None:
    """Remove the containers, volumes and network the BATS tier creates."""
    sweeps = (
        (["docker", "ps", "-aq"], ["docker", "rm", "-f"]),
        (["docker", "volume", "ls", "-q"], ["docker", "volume", "rm", "-f"]),
        (["docker", "network", "ls", "-q"], ["docker", "network", "rm"]),
    )
    removed = 0
    for list_cmd, remove_cmd in sweeps:
        listing = subprocess.run(
            [*list_cmd, "--filter", f"name={INTEGRATION_PREFIX}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        ids = listing.stdout.split()
        if ids:
            removed += len(ids)
            subprocess.run(
                [*remove_cmd, *ids],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
    print(f"integration: removed {removed} object(s) named {INTEGRATION_PREFIX}*")


def clean_k8s() -> None:
    """Uninstall culvert releases and remove the pods this tier creates."""
    sys.path.insert(0, str(TESTS_DIR))
    # Importing the conftest loads tests/k8s/.env, which is where the context
    # and namespace come from.
    k8s = _load("culvert_k8s_conftest", TESTS_DIR / "k8s" / "conftest.py")
    context = os.environ.get("CULVERT_K8S_CONTEXT", "").strip()
    if not context:
        print("k8s: CULVERT_K8S_CONTEXT is not set, nothing to clean", file=sys.stderr)
        return
    namespace = os.environ.get("CULVERT_K8S_NAMESPACE", k8s.DEFAULT_NAMESPACE)
    k8s.sweep(context, namespace)
    print(f"k8s: culvert releases and tier pods removed from {namespace}")


CLEANERS = {
    "docker": clean_docker,
    "integration": clean_integration,
    "k8s": clean_k8s,
}


def main(argv: list[str]) -> int:
    """Run the requested tier cleanups."""
    tiers = argv[1:] or list(CLEANERS)
    unknown = [t for t in tiers if t not in CLEANERS]
    if unknown:
        print(f"unknown tier(s): {', '.join(unknown)}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    for tier in CLEANERS:
        if tier in tiers:
            CLEANERS[tier]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
