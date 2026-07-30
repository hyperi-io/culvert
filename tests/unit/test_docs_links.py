#  Project:      culvert
#  File:         test_docs_links.py
#  Purpose:      Markdown links resolve, case-sensitively, and docs/ is named right
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Documentation structure and link integrity.

The case check is the point. macOS is case-insensitive, so a link left
pointing at ``docs/ADDRESSING.md`` after a rename resolves perfectly on the
machine that wrote it and 404s on GitHub and on every Linux runner. Comparing
against git's index rather than the filesystem is what makes the check real.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

# Untracked and gitignored: a planning archive that never ships.
EXCLUDED = ("docs/superpowers/",)

# Root meta-files keep the conventional uppercase GitHub recognises.
ROOT_META = {
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "CLAUDE.md",
}


def _tracked() -> set[str]:
    """Every tracked path, with the exact case git records."""
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("not a git checkout, so exact-case paths are unavailable")
    return {p for p in result.stdout.split() if p}


def _normalise(base: PurePosixPath, target: str) -> str:
    """Resolve a relative link without touching the filesystem."""
    parts: list[str] = []
    for part in (base / target.rstrip("/")).parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


@pytest.fixture(scope="module")
def tracked() -> set[str]:
    return _tracked()


class TestMarkdownLinks:
    """Every relative link in a tracked markdown file points at something real."""

    def test_no_broken_relative_links(self, tracked):
        directories = {str(PurePosixPath(p).parent) for p in tracked}
        sources = [
            p for p in tracked if p.endswith(".md") and not p.startswith(EXCLUDED)
        ]
        assert sources, "no tracked markdown found, so this test proves nothing"

        broken = []
        for rel in sorted(sources):
            path = ROOT / rel
            if not path.is_file():
                continue
            parent = PurePosixPath(rel).parent
            for target in LINK.findall(path.read_text(encoding="utf-8")):
                if target.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                clean = target.split("#", 1)[0]
                if not clean:
                    continue
                resolved = _normalise(parent, clean)
                if resolved not in tracked and resolved not in directories:
                    broken.append(f"{rel} -> {target}")

        assert not broken, "broken relative link(s):\n  " + "\n  ".join(broken)


class TestDocsNaming:
    """docs/ content is lowercase-kebab, and the directory has a landing page."""

    def test_content_is_lowercase_kebab(self, tracked):
        offenders = [
            p
            for p in tracked
            if p.startswith("docs/")
            and not p.startswith(EXCLUDED)
            and p.endswith(".md")
            and PurePosixPath(p).name not in ROOT_META
            and PurePosixPath(p).name != PurePosixPath(p).name.lower()
        ]
        assert not offenders, (
            "docs/ filenames become URL slugs and static-site generators"
            " lowercase them, so uppercase names break links:\n  "
            + "\n  ".join(offenders)
        )

    def test_no_underscores_in_docs_filenames(self, tracked):
        offenders = [
            p
            for p in tracked
            if p.startswith("docs/")
            and not p.startswith(EXCLUDED)
            and p.endswith(".md")
            and "_" in PurePosixPath(p).name
        ]
        assert not offenders, (
            "search tooling reads '-' as a word boundary and '_' as part of the"
            " token, so hyphenate:\n  " + "\n  ".join(offenders)
        )

    def test_docs_has_a_landing_page(self, tracked):
        assert "docs/README.md" in tracked, (
            "docs/ needs a README.md landing page - it is the folder index"
            " GitHub renders and the entry point the root README links to"
        )

    def test_landing_page_links_every_doc(self, tracked):
        """An index that misses a file leaves that file undiscoverable."""
        index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        linked = {
            t.split("#", 1)[0] for t in LINK.findall(index) if not t.startswith("http")
        }
        missing = [
            PurePosixPath(p).name
            for p in sorted(tracked)
            if p.startswith("docs/")
            and not p.startswith(EXCLUDED)
            and p.endswith(".md")
            and PurePosixPath(p).name != "README.md"
            and PurePosixPath(p).name not in linked
        ]
        assert not missing, "docs/README.md does not link:\n  " + "\n  ".join(missing)
