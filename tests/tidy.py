#  Project:      culvert
#  File:         tidy.py
#  Purpose:      Session-end cleanup registry for tiers that build real infra
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Cleanup registry for the tiers that create real infrastructure.

The docker and Kubernetes tiers stand up containers, volumes, networks, pods
and Helm releases. A fixture finaliser is skipped when the process is
signalled, which is how an interrupted run left containers on the build host
and a Helm release on the cluster. Cleanups registered here instead run from
``pytest_sessionfinish``, which pytest reaches on a normal finish, a collection
error, Ctrl-C, and - once ``install_signal_handler`` has run - SIGTERM.

SIGKILL cannot be trapped by anything, so this is not a total guarantee. The
guarantee is on the other side: each tier sweeps what it owns BEFORE it builds,
so a run that was killed outright cannot poison the next one.
"""

from __future__ import annotations

import signal
import sys
from collections.abc import Callable

_TEARDOWNS: list[tuple[str, Callable[[], None]]] = []


def register_teardown(name: str, func: Callable[[], None]) -> None:
    """Register a cleanup to run at session end however the session ends."""
    _TEARDOWNS.append((name, func))


def run_teardowns() -> None:
    """Run every registered cleanup, newest first, reporting failures.

    One cleanup failing must not skip the others, so nothing is raised - a
    teardown that cannot complete prints why and the next one still runs.
    """
    while _TEARDOWNS:
        name, func = _TEARDOWNS.pop()
        try:
            func()
        except Exception as exc:  # noqa: BLE001 - see docstring
            print(f"\nteardown {name} failed: {exc}", file=sys.stderr)


def install_signal_handler() -> None:
    """Make SIGTERM unwind through pytest instead of killing it outright.

    Ctrl-C already raises KeyboardInterrupt, which pytest turns into an orderly
    shutdown. SIGTERM - what a CI cancellation, a timeout wrapper or a plain
    ``kill`` sends - terminates the interpreter with no unwinding, so nothing is
    torn down. Converting it to the same exception buys the same shutdown.
    """
    if signal.getsignal(signal.SIGTERM) is signal.SIG_DFL:
        signal.signal(signal.SIGTERM, _raise_interrupt)


def _raise_interrupt(signum: int, frame: object) -> None:
    """Signal handler: unwind the session so the teardowns run."""
    raise KeyboardInterrupt(f"signal {signum}")
