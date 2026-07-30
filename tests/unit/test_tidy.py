#  Project:      culvert
#  File:         test_tidy.py
#  Purpose:      Cleanup must survive the signals that interrupt a test run
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""The teardown registry, and its behaviour under signals.

These are the guarantees that keep an interrupted docker or cluster run from
leaving infrastructure behind: cleanups run however the session ends, a signal
arriving mid-cleanup cannot cut it short, and one failing cleanup neither skips
the others nor goes unretried.
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tidy  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_registry():
    """Keep these tests from leaking teardowns into each other or the session."""
    saved = list(tidy._TEARDOWNS)
    tidy._TEARDOWNS.clear()
    yield
    tidy._TEARDOWNS.clear()
    tidy._TEARDOWNS.extend(saved)


@pytest.fixture(autouse=True)
def _restore_handlers():
    """Restore signal handlers, since these tests deliberately move them."""
    original = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    yield
    for signum, handler in original.items():
        signal.signal(signum, handler)


class TestRunTeardowns:
    """Ordering, isolation and retry."""

    def test_runs_newest_first(self):
        order = []
        tidy.register_teardown("first", lambda: order.append("first"))
        tidy.register_teardown("second", lambda: order.append("second"))
        tidy.run_teardowns()
        assert order == ["second", "first"], (
            "teardowns must unwind in reverse registration order, so a stack"
            " built in dependency order comes down safely"
        )

    def test_registry_is_emptied(self):
        tidy.register_teardown("once", lambda: None)
        tidy.run_teardowns()
        assert tidy._TEARDOWNS == [], "a second call would repeat the cleanup"

    def test_one_failure_does_not_skip_the_others(self):
        done = []

        def boom():
            raise RuntimeError("compose down exploded")

        tidy.register_teardown("survivor", lambda: done.append("survivor"))
        tidy.register_teardown("boom", boom)
        tidy.run_teardowns()
        assert done == ["survivor"], (
            "a failing teardown aborted the rest, so anything registered"
            " earlier was never cleaned up"
        )

    def test_a_failing_teardown_is_retried_once(self):
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("interrupted part-way")

        tidy.register_teardown("flaky", flaky)
        tidy.run_teardowns()
        assert len(attempts) == 2, (
            "a cleanup interrupted part-way is not retried, so the half-removed"
            " stack stays behind"
        )

    def test_keyboardinterrupt_in_a_teardown_is_contained(self):
        """KeyboardInterrupt is not an Exception, so it needs naming explicitly."""
        done = []

        def interrupted():
            raise KeyboardInterrupt("signal 15")

        tidy.register_teardown("survivor", lambda: done.append("survivor"))
        tidy.register_teardown("interrupted", interrupted)
        tidy.run_teardowns()
        assert done == ["survivor"]


class TestSignalsDuringCleanup:
    """Cleanup is the critical section: a signal must not cut it short."""

    @pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
    def test_signals_are_ignored_while_a_teardown_runs(self, signum):
        """A signal landing mid-teardown must not abort it.

        Unignored, a SIGTERM arriving during ``docker compose down`` kills the
        cleanup and leaves the containers up. Signalling from inside a teardown
        is that situation exactly: if the signal is not ignored, the teardown
        never completes.
        """
        observed = {}

        def teardown():
            observed["handler"] = signal.getsignal(signum)
            signal.raise_signal(signum)
            observed["survived"] = True

        tidy.register_teardown("self-signalling", teardown)
        tidy.run_teardowns()

        assert observed.get("handler") is signal.SIG_IGN, (
            f"{signum!r} was not ignored during cleanup, so a signal arriving"
            " mid-teardown can still abort it"
        )
        assert observed.get("survived"), "the teardown did not run to completion"

    @pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
    def test_handlers_are_restored_afterwards(self, signum):
        """Ignoring signals must not outlive cleanup."""
        sentinel = signal.getsignal(signum)
        tidy.register_teardown("noop", lambda: None)
        tidy.run_teardowns()
        assert signal.getsignal(signum) is sentinel


class TestSigtermHandler:
    """SIGTERM has to unwind pytest, and disarm itself doing it."""

    def test_handler_is_installed_when_default(self):
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        tidy.install_signal_handler()
        assert signal.getsignal(signal.SIGTERM) is tidy._raise_interrupt

    def test_an_existing_handler_is_left_alone(self):
        def mine(signum, frame):
            pass

        signal.signal(signal.SIGTERM, mine)
        tidy.install_signal_handler()
        assert signal.getsignal(signal.SIGTERM) is mine, (
            "installing over someone else's handler would break whatever"
            " already owned the signal"
        )

    def test_handler_disarms_itself_before_raising(self):
        """A repeat signal must not land inside the cleanup the first one began.

        Supervisors escalate, people press Ctrl-C twice, and signals go to the
        whole process group - so a second SIGTERM is the normal case, not the
        exotic one.
        """
        signal.signal(signal.SIGTERM, tidy._raise_interrupt)
        with pytest.raises(KeyboardInterrupt):
            tidy._raise_interrupt(signal.SIGTERM, None)
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_IGN
