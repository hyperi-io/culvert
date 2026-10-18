#  Project:      culvert
#  File:         test_teardown_volumes.py
#  Purpose:      Test teardowns remove a container's volumes along with it
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Test teardowns remove a container's anonymous volumes along with it.

The image declares ``VOLUME`` for four paths, so a test container gets an
anonymous volume for each one it does not mount. ``docker rm`` and
``docker compose down`` leave those behind unless given ``-v``, and every run
adds another set to the build host's disk.
"""

import ast
import re
from itertools import takewhile
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
SOURCE_SUFFIXES = (".py", ".sh", ".bash", ".bats")

# A short-flag cluster that includes -v, such as -fv.
VOLUMES_SHORT = re.compile(r"-[A-Za-z]*v[A-Za-z]*")

# A shell word that ends a command's own arguments: pipe, list, redirection.
SHELL_STOP = re.compile(r"^[|;&<>#)]|>")

type Words = list[str | None]


def _removal_flags(words: Words) -> Words | None:
    """The arguments of a container removal, or None for any other command.

    ``words`` runs from ``docker`` on, with None for a word that is not a
    string literal.
    """
    if words[0] == "docker-compose":
        rest = ["compose", *words[1:]]
    else:
        rest = words[1:]
    if rest[:1] == ["container"]:
        rest = rest[1:]
    if rest[:1] == ["rm"]:
        return rest[1:]
    if rest[:1] == ["compose"] and "down" in rest:
        return rest[rest.index("down") + 1 :]
    return None


def _removes_volumes(flags: Words) -> bool:
    """True when a removal's arguments carry -v or --volumes."""
    return any(
        word == "--volumes" or (word is not None and VOLUMES_SHORT.fullmatch(word))
        for word in flags
    )


def _shell_commands(text: str) -> list[tuple[int, Words]]:
    """Docker commands in shell source, with continuation lines joined."""
    found: list[tuple[int, Words]] = []
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        logical, pending = pending + line, ""
        if logical.lstrip().startswith("#"):
            continue
        words = logical.split()
        for index, word in enumerate(words):
            if word in ("docker", "docker-compose"):
                command = takewhile(lambda w: not SHELL_STOP.search(w), words[index:])
                found.append((start, list(command)))
    return found


def _literal(node: ast.expr) -> str | None:
    """A string literal's value, or None for any other expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _python_commands(text: str) -> list[tuple[int, Words]]:
    """Docker argv literals in Python source: lists or tuples led by "docker"."""
    found: list[tuple[int, Words]] = []
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, ast.List | ast.Tuple) or not node.elts:
            continue
        words = [_literal(elt) for elt in node.elts]
        if words[0] in ("docker", "docker-compose"):
            found.append((node.lineno, words))
    return found


def _test_sources() -> list[Path]:
    """Test-tree sources that can run docker, minus this file's deliberate bad samples."""
    this_file = Path(__file__).resolve()
    return sorted(
        path
        for path in TESTS.rglob("*")
        if path.suffix in SOURCE_SUFFIXES
        and "__pycache__" not in path.parts
        and path.resolve() != this_file
    )


class TestTeardownRemovesVolumes:
    """Every container removal under tests/ takes the container's volumes too."""

    def test_every_removal_carries_volumes_flag(self):
        removals = 0
        offenders = []
        for path in _test_sources():
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".py":
                commands = _python_commands(text)
            else:
                commands = _shell_commands(text)
            for line, words in commands:
                flags = _removal_flags(words)
                if flags is None:
                    continue
                removals += 1
                if not _removes_volumes(flags):
                    where = f"{path.relative_to(TESTS.parent)}:{line}"
                    shown = " ".join(word or "<expr>" for word in words)
                    offenders.append(f"{where}: {shown}")

        assert removals, "no container removal under tests/, so this proves nothing"
        assert not offenders, (
            "container removed without -v, so its anonymous volumes stay behind:\n  "
            + "\n  ".join(offenders)
        )


class TestRemovalDetection:
    """The detector the guard above relies on, against known shapes."""

    @pytest.mark.parametrize(
        ("command", "strips"),
        [
            ("docker rm -f x", True),
            ("docker rm -fv x", False),
            ("docker rm -f --volumes x", False),
            ("docker container rm -f x", True),
            ("docker compose -f a.yml -p p down --remove-orphans", True),
            ("docker compose -f a.yml -p p down -v", False),
            ("docker-compose down", True),
        ],
    )
    def test_container_removal(self, command, strips):
        flags = _removal_flags(command.split())
        assert flags is not None
        assert _removes_volumes(flags) is not strips

    @pytest.mark.parametrize(
        "command",
        [
            "docker rmi culvert:test",
            "docker volume rm -f x",
            "docker network rm x",
            "docker compose -f a.yml up -d",
            "docker run -d --name x img",
        ],
    )
    def test_not_a_container_removal(self, command):
        assert _removal_flags(command.split()) is None

    def test_python_argv_with_expressions(self):
        source = 'cmd = ["docker", "compose", "-f", str(path), "down", "-v"]\n'
        [(line, words)] = _python_commands(source)
        assert line == 1
        assert words[3] is None
        flags = _removal_flags(words)
        assert flags is not None
        assert _removes_volumes(flags)

    def test_shell_stops_at_redirection_and_skips_comments(self):
        source = (
            "# docker rm -f in a comment\n"
            'docker rm -f "${NAME}" >/dev/null 2>&1 || true\n'
        )
        assert _shell_commands(source) == [(2, ["docker", "rm", "-f", '"${NAME}"'])]

    def test_shell_joins_continuation_lines(self):
        source = "true\ndocker rm \\\n    -fv x\n"
        assert _shell_commands(source) == [(2, ["docker", "rm", "-fv", "x"])]
