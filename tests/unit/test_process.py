#  Project:      culvert
#  File:         test_process.py
#  Purpose:      Tests for process management module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import stat
import subprocess

import pytest
from lib.process import (
    ProcessManager,
    run,
    run_quiet,
    setup_directories,
    setup_scripts,
    write_secret,
)


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


class TestRunQuiet:
    """Tests for run_quiet() convenience helper."""

    def test_returns_true_on_success(self):
        """Successful command returns True."""
        assert run_quiet("true") is True

    def test_returns_false_on_failure(self):
        """Failed command returns False (no exception)."""
        assert run_quiet("false") is False

    def test_returns_true_for_list_command(self):
        """Works with list-style commands."""
        assert run_quiet(["echo", "test"]) is True


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

    def test_start_tracks_process(self):
        """Started processes are tracked in the processes dict."""
        pm = ProcessManager()
        proc = pm.start("test-sleep", ["sleep", "60"], daemon=True)
        assert proc is not None
        assert "test-sleep" in pm.processes
        proc.kill()
        proc.wait()

    def test_start_returns_none_on_bad_command(self):
        """Invalid commands return None."""
        pm = ProcessManager()
        proc = pm.start("bad", ["/nonexistent/binary/xyz123"], daemon=True)
        assert proc is None

    def test_wait_for_main_returns_exit_code(self):
        """wait_for_main returns process exit code."""
        pm = ProcessManager()
        pm.start("quick-exit", ["true"], daemon=False)
        code = pm.wait_for_main("quick-exit")
        assert code == 0

    def test_wait_for_main_nonexistent_returns_1(self):
        """Waiting on unknown process returns 1."""
        pm = ProcessManager()
        assert pm.wait_for_main("nonexistent") == 1

    def test_shutdown_requested_flag(self):
        """shutdown_requested starts as False."""
        pm = ProcessManager()
        assert pm.shutdown_requested is False
