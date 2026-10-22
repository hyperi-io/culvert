#  Project:      culvert
#  File:         tests/unit/test_requirements_docker.py
#  Purpose:      Hold the image's requirements file to the lockfile it is exported from
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED
"""The Dockerfile installs requirements-docker.txt, not uv.lock, so the two must match."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The command recorded in requirements-docker.txt's own header.
EXPORT = [
    "uv",
    "export",
    "--frozen",
    "--no-dev",
    "--no-emit-project",
    "--extra",
    "otel",
    "--format",
    "requirements-txt",
]


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not installed")
def test_requirements_docker_matches_the_lockfile() -> None:
    exported = subprocess.run(
        EXPORT,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    committed = (ROOT / "requirements-docker.txt").read_text(encoding="utf-8")

    def pins(text: str) -> list[str]:
        return [line for line in text.splitlines() if line and not line.startswith("#")]

    assert pins(committed) == pins(exported), (
        "requirements-docker.txt is out of step with uv.lock; regenerate it with: "
        "uv export --frozen --no-dev --no-emit-project --extra otel "
        "--format requirements-txt -o requirements-docker.txt"
    )
