#  Project:      culvert
#  File:         doc_values.py
#  Purpose:      Read the Helm values the Kubernetes walkthrough documents
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""The values docs/use-case-kubernetes.md tells an operator to install.

The walkthrough is the one place the chart's values are written down, because
the chart is published rather than committed. The unit tier checks them against
the contract and Config, and the cluster tier installs them, so both read the
document itself instead of keeping a second copy that can drift from it.
"""

import re
from pathlib import Path

import yaml

DOC = Path(__file__).resolve().parents[1] / "docs" / "use-case-kubernetes.md"
_FENCE = re.compile(r"^```yaml\n(.*?)^```", re.DOTALL | re.MULTILINE)


def doc_text() -> str:
    """The walkthrough, as written."""
    return DOC.read_text(encoding="utf-8")


def _blocks() -> list[dict]:
    return [yaml.safe_load(block) for block in _FENCE.findall(doc_text())]


def _only(blocks: list[dict], what: str) -> dict:
    if len(blocks) != 1:
        raise LookupError(
            f"expected exactly one {what} in {DOC.name}, found {len(blocks)}"
        )
    return blocks[0]


def install_values() -> dict:
    """The install values: the one block that sets `configMount`."""
    return _only([b for b in _blocks() if "configMount" in b], "install values block")


def external_pki_values() -> dict:
    """The external PKI values: the one block that sets CULVERT_PKI_MODE."""
    return _only(
        [b for b in _blocks() if "CULVERT_PKI_MODE" in b.get("extraEnv", {})],
        "external PKI values block",
    )
