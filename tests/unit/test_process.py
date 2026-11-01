#  Project:      culvert
#  File:         test_process.py
#  Purpose:      Tests for process management module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import shutil
import signal
import stat
import subprocess
import time
from types import SimpleNamespace

import pytest
from lib.process import (
    run,
    setup_directories,
    setup_scripts,
    write_file_atomic,
    write_secret,
)


class TestWriteFileAtomic:
    def test_replaces_with_the_mode_and_leaves_no_temp_file(self, tmp_path):
        target = tmp_path / "ca.crt"
        target.write_bytes(b"old")
        write_file_atomic(target, b"new", 0o644)

        assert target.read_bytes() == b"new"
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
        assert [p.name for p in tmp_path.iterdir()] == ["ca.crt"]

    def test_does_not_use_another_writers_temp_file(self, tmp_path):
        """Writers sharing a PKI directory each get their own temp file."""
        target = tmp_path / "ca.crt"
        other = tmp_path / ".ca.crt.tmp"
        other.write_bytes(b"half written by another container")
        write_file_atomic(target, b"new", 0o644)

        assert other.read_bytes() == b"half written by another container"

    def test_flushes_the_file_and_then_the_directory(self, tmp_path, monkeypatch):
        """Without both, a power cut can leave the name pointing at an empty file."""
        import os

        synced = []
        real_fsync = os.fsync

        def recording_fsync(fd):
            synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", recording_fsync)
        write_file_atomic(tmp_path / "allocations.json", b"{}", 0o644)

        assert synced == [False, True]


class TestWriteSecret:
    """write_secret's defining property: 0600 with no wider-perms window."""

    def test_new_file_created_0600(self, tmp_path):
        target = tmp_path / "secret.txt"
        write_secret(target, "hunter2")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert target.read_text(encoding="utf-8") == "hunter2"

    def test_preexisting_wider_perms_tightened(self, tmp_path):
        """A pre-existing 0644 file must end up 0600 (the fchmod path)."""
        target = tmp_path / "secret.txt"
        target.write_text("old", encoding="utf-8")
        target.chmod(0o644)
        write_secret(target, "new-secret")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert target.read_text(encoding="utf-8") == "new-secret"


class TestRun:
    """Tests for the run() shell command helper."""

    def test_runs_string_command(self):
        """String commands are wrapped in sh -c."""
        result = run("echo hello", capture=True)
        assert result.stdout.strip() == "hello"

    def test_runs_list_command(self):
        """List commands are passed directly."""
        result = run(["echo", "world"], capture=True)
        assert result.stdout.strip() == "world"

    def test_raises_on_failure_by_default(self):
        """check=True raises CalledProcessError."""
        with pytest.raises(subprocess.CalledProcessError):
            run("false", check=True)

    def test_no_raise_with_check_false(self):
        """check=False returns non-zero without exception."""
        result = run("false", check=False)
        assert result.returncode != 0

    def test_capture_false_returns_no_output(self):
        """Without capture, stdout is None."""
        result = run("echo test", capture=False)
        assert result.stdout is None

    def test_captures_stderr(self):
        """Captures stderr from failing commands."""
        result = run("echo err >&2 && false", check=False, capture=True)
        assert "err" in result.stderr


class TestSetupDirectories:
    """Tests for directory creation."""

    def test_creates_all_directories(self, tmp_path):
        """All required directories are created."""

        class FakeCfg:
            pki_dir = tmp_path / "pki"
            ccd_dir = tmp_path / "ccd"
            log_dir = tmp_path / "log"
            run_dir = tmp_path / "run"

        setup_directories(FakeCfg())

        assert FakeCfg.pki_dir.exists()
        assert (FakeCfg.pki_dir / "issued").exists()
        assert (FakeCfg.pki_dir / "private").exists()
        assert (FakeCfg.pki_dir / "reqs").exists()
        assert FakeCfg.ccd_dir.exists()
        assert FakeCfg.log_dir.exists()
        assert FakeCfg.run_dir.exists()

    def test_idempotent(self, tmp_path):
        """Calling twice does not fail."""

        class FakeCfg:
            pki_dir = tmp_path / "pki"
            ccd_dir = tmp_path / "ccd"
            log_dir = tmp_path / "log"
            run_dir = tmp_path / "run"

        setup_directories(FakeCfg())
        setup_directories(FakeCfg())  # Second call should not raise


@pytest.mark.skipif(shutil.which("logrotate") is None, reason="needs logrotate")
class TestLogRotation:
    """PID 1 is Python with no cron, so culvert runs logrotate itself."""

    def test_rotates_while_the_writer_keeps_its_file_open(self, tmp_path):
        """OpenVPN and the daemons hold an O_APPEND fd that is never reopened."""
        from lib.process import rotate_logs, setup_log_rotation

        cfg = SimpleNamespace(log_dir=tmp_path)
        conf, state = setup_log_rotation(cfg, conf_path=tmp_path / "logrotate.conf")
        log = tmp_path / "openvpn.log"
        status = tmp_path / "status.log"
        status.write_text("CLIENT_LIST\talice\n")
        with log.open("ab") as writer:
            writer.write(b"before rotation\n")
            writer.flush()
            assert rotate_logs(conf, state, force=True)
            writer.write(b"after rotation\n")

        assert (tmp_path / "openvpn.log.1").read_bytes() == b"before rotation\n"
        assert log.read_bytes() == b"after rotation\n"
        assert status.read_text() == "CLIENT_LIST\talice\n"
        assert not (tmp_path / "status.log.1").exists()

    def test_the_schedule_runs_logrotate(self, tmp_path):
        from lib.process import setup_log_rotation, start_log_rotation

        cfg = SimpleNamespace(log_dir=tmp_path)
        conf, state = setup_log_rotation(cfg, conf_path=tmp_path / "logrotate.conf")
        (tmp_path / "openvpn.log").write_text("line\n")

        start_log_rotation(conf, state, interval=0.05)

        deadline = time.monotonic() + 10
        while not state.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert state.exists(), "logrotate never ran, so no state file was written"


class TestSetupScripts:
    """Tests for script permission setup."""

    def test_makes_existing_scripts_executable(self, tmp_path):
        """Existing scripts get 0o755 permissions."""
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()
        connect = scripts_dir / "client-connect.sh"
        connect.write_text("#!/bin/bash\n")
        connect.chmod(0o644)

        class FakeCfg:
            scripts_dir = None

        FakeCfg.scripts_dir = scripts_dir

        setup_scripts(FakeCfg())
        assert connect.stat().st_mode & 0o755 == 0o755

    def test_ignores_missing_scripts(self, tmp_path):
        """Missing scripts don't cause errors."""

        class FakeCfg:
            scripts_dir = tmp_path / "empty_scripts"

        FakeCfg.scripts_dir.mkdir()
        setup_scripts(FakeCfg())  # Should not raise


class TestProcessManager:
    """Tests for ProcessManager lifecycle."""

    def test_start_tracks_process(self, manager):
        """Started processes are tracked in the processes dict."""
        proc = manager.start("test-sleep", ["sleep", "60"], daemon=True)
        assert proc is not None
        assert "test-sleep" in manager.processes

    def test_start_returns_none_on_bad_command(self, manager):
        """Invalid commands return None."""
        proc = manager.start("bad", ["/nonexistent/binary/xyz123"], daemon=True)
        assert proc is None

    def test_wait_for_main_returns_exit_code(self, manager):
        """wait_for_main returns process exit code."""
        manager.start("quick-exit", ["true"], daemon=False)
        code = manager.wait_for_main("quick-exit")
        assert code == 0

    def test_wait_for_main_nonexistent_returns_1(self, manager):
        """Waiting on unknown process returns 1."""
        assert manager.wait_for_main("nonexistent") == 1

    def test_shutdown_requested_flag(self, manager):
        """shutdown_requested starts as False."""
        assert manager.shutdown_requested is False


class TestUnhealthy:
    """unhealthy() names every child that never started or has since exited."""

    def test_running_children_are_healthy(self, manager):
        manager.start("openvpn-udp", ["sleep", "30"])
        manager.start("stunnel", ["sleep", "30"], daemon=True)
        assert manager.unhealthy() == []

    def test_an_exited_child_is_named(self, manager):
        manager.start("openvpn-udp", ["sleep", "30"])
        quick = manager.start("wstunnel", ["true"], daemon=True)
        quick.wait(timeout=10)
        assert manager.unhealthy() == ["wstunnel"]

    def test_a_failed_start_is_named(self, manager):
        manager.start("oauth2-udp", ["/nonexistent/binary/xyz123"], daemon=True)
        assert manager.unhealthy() == ["oauth2-udp"]

    def test_a_later_good_start_clears_the_failure(self, manager):
        manager.start("stunnel", ["/nonexistent/binary/xyz123"], daemon=True)
        manager.start("stunnel", ["sleep", "30"], daemon=True)
        assert manager.unhealthy() == []


class TestDaemonLogs:
    """A daemon's output goes to a file, never an unread pipe that blocks it."""

    def test_output_lands_in_a_log_readable_only_by_the_group(self, manager, tmp_path):
        manager.config = SimpleNamespace(log_dir=tmp_path, protocol="openvpn")
        proc = manager.start("echoer", ["sh", "-c", "echo hello"], daemon=True)
        assert proc is not None
        proc.wait(timeout=10)

        log = tmp_path / "echoer.log"
        assert log.read_text(encoding="utf-8") == "hello\n"
        assert stat.S_IMODE(log.stat().st_mode) == 0o640

    def test_unopenable_log_still_starts_the_daemon(self, manager, tmp_path):
        manager.config = SimpleNamespace(
            log_dir=tmp_path / "absent", protocol="openvpn"
        )
        proc = manager.start("quiet", ["true"], daemon=True)
        assert proc is not None
        assert proc.wait(timeout=10) == 0
        assert not (tmp_path / "absent").exists()


class TestShutdown:
    """Shutdown stops every child and exits with the code the caller chose."""

    def test_children_are_stopped_and_the_code_is_returned(self, manager):
        from lib.health import health

        proc = manager.start("sleeper", ["sleep", "30"])
        health.set_ready(True)
        with pytest.raises(SystemExit) as exc_info:
            manager.shutdown(3)

        assert exc_info.value.code == 3
        assert proc.poll() == -signal.SIGTERM
        assert health.is_ready() is False

    def test_sigterm_handler_shuts_down_cleanly(self, manager):
        proc = manager.start("sleeper", ["sleep", "30"])
        with pytest.raises(SystemExit) as exc_info:
            manager._signal_handler(signal.SIGTERM, None)

        assert exc_info.value.code == 0
        assert manager.shutdown_requested is True
        assert proc.poll() is not None

    @pytest.mark.parametrize(
        ("name", "receives"),
        [
            ("openvpn-udp", True),
            ("openvpn-https", True),
            ("stunnel", True),
            # No SIGHUP handler: the signal kills it and nothing restarts it.
            ("wstunnel", False),
            ("oauth2-udp", False),
        ],
    )
    def test_sighup_reaches_only_children_that_reload(self, manager, name, receives):
        """OpenVPN re-reads its CRL on SIGHUP, and a child without a handler dies."""
        proc = manager.start(name, ["sleep", "30"])
        manager._reload_handler(signal.SIGHUP, None)
        if receives:
            assert proc.wait(timeout=10) == -signal.SIGHUP
        else:
            with pytest.raises(subprocess.TimeoutExpired):
                proc.wait(timeout=1)


class TestDrain:
    """SIGTERM drops readiness, gives load balancers time, then stops the children.

    Stopping at once lets a load balancer that has not yet seen readiness drop
    send a client to a server that is already gone.
    """

    @staticmethod
    def _draining(manager, drain_seconds, connected):
        """Record, at each count, whether the child is up and the pod is ready."""
        from lib.health import health

        manager.config = SimpleNamespace(
            drain_seconds=drain_seconds, protocol="openvpn"
        )
        child = manager.start("openvpn-udp", ["sleep", "30"])
        seen = []

        def count():
            seen.append((child.poll() is None, health.is_ready()))
            return connected

        health.set_ready(True)
        return child, seen, count

    def test_children_serve_through_the_drain_while_clients_are_connected(
        self, manager
    ):
        child, seen, count = self._draining(manager, drain_seconds=2, connected=3)

        started = time.monotonic()
        with pytest.raises(SystemExit):
            manager._signal_handler(signal.SIGTERM, None, count_connected=count)

        assert time.monotonic() - started >= 2
        assert seen and all(alive and not ready for alive, ready in seen)
        assert child.poll() is not None

    def test_the_drain_ends_once_no_client_is_connected(self, manager):
        _, seen, count = self._draining(manager, drain_seconds=30, connected=0)

        started = time.monotonic()
        with pytest.raises(SystemExit):
            manager._signal_handler(signal.SIGTERM, None, count_connected=count)

        assert time.monotonic() - started < 10
        assert len(seen) == 1

    def test_a_second_signal_stops_without_finishing_the_drain(self, manager):
        child, _, count = self._draining(manager, drain_seconds=30, connected=3)

        def second_signal():
            count()
            manager._signal_handler(signal.SIGTERM, None)
            return 3

        started = time.monotonic()
        with pytest.raises(SystemExit):
            manager._signal_handler(signal.SIGTERM, None, count_connected=second_signal)

        assert time.monotonic() - started < 10
        assert child.poll() is not None

    def test_children_share_one_stop_deadline(self, manager):
        """Sequential per-child timeouts outlast a 30 second grace period."""
        manager.stop_timeout = 1
        for name in ("openvpn-udp", "openvpn-tcp", "stunnel"):
            manager.start(name, ["sh", "-c", "trap '' TERM; sleep 30"])
        time.sleep(0.2)

        started = time.monotonic()
        with pytest.raises(SystemExit):
            manager.shutdown()

        assert time.monotonic() - started < 3
        assert all(
            proc.poll() == -signal.SIGKILL for proc in manager.processes.values()
        )
