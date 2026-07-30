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
signalled, so an interrupted run leaves containers on the build host and a Helm
release on the cluster. Cleanups registered here instead run from
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

    Cleanup is a critical section, so SIGINT and SIGTERM are IGNORED for its
    duration. Without that, a signal arriving while ``docker compose down`` is
    running aborts it part-way and leaves behind exactly the containers this
    exists to remove. Catching the interrupt is not enough: that protects the
    REMAINING teardowns, not the one already in flight.

    Each cleanup is retried once, because a failure often means it got part of
    the way. They are all idempotent. Nothing propagates: one cleanup failing
    must not skip the others.
    """
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.signal(signum, signal.SIG_IGN)
        except (ValueError, OSError):
            # Not the main thread, or the platform refuses - press on unguarded
            # rather than skipping cleanup altogether.
            pass
    try:
        while _TEARDOWNS:
            name, func = _TEARDOWNS.pop()
            for attempt in (1, 2):
                try:
                    func()
                    break
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001
                    if attempt == 2:
                        print(
                            f"\nteardown {name} failed twice, giving up: {exc}"
                            "\nrun `python3 tests/cleanup.py` to clear it",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"\nteardown {name} failed, retrying: {exc}",
                            file=sys.stderr,
                        )
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass


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
    """Signal handler: unwind the session once, then stop listening.

    Disarming before raising matters. Whatever sent the first signal often sends
    another - a supervisor escalating, a `kill` repeated, a signal delivered to
    the whole process group - and the second one would land inside the cleanup
    this first one triggered, interrupting `docker compose down` part-way and
    leaving exactly the containers the handler exists to remove.

    Ignoring rather than restoring the default is deliberate: the default action
    for SIGTERM is to die immediately, which is the outcome being avoided. The
    cleanups all run subprocesses with timeouts, so this cannot wait forever.
    """
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt(f"signal {signum}")
