#  Project:      culvert
#  File:         process.py
#  Purpose:      Process management, signal handling, and shell command helpers
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Process management for culvert container.

Provides ProcessManager for supervised child processes with graceful
shutdown, plus run()/run_quiet() shell command helpers and directory/
log rotation setup functions.
"""

import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO

from scalo.logger import logger


def run(
    cmd: str | list, check: bool = True, capture: bool = False
) -> subprocess.CompletedProcess:
    """Run a shell command."""
    if isinstance(cmd, str):
        cmd = ["sh", "-c", cmd]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def run_quiet(cmd: str | list) -> bool:
    """Run a command and return True if successful."""
    try:
        run(cmd, check=True, capture=True)
        return True
    except subprocess.CalledProcessError:
        return False


def write_secret(path: Path | str, content: str) -> None:
    """Write secret material with 0600 permissions from creation.

    A plain write_text()-then-chmod() leaves the file readable at the
    default umask between the two calls; opening with mode 0o600 (and
    fchmod for pre-existing files) closes that window.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def setup_directories(cfg) -> None:
    """Create required directories."""
    logger.info("Setting up directories...")

    run_dir = getattr(cfg, "run_dir", Path("/run/vpn"))
    dirs = [
        cfg.pki_dir,
        cfg.pki_dir / "issued",
        cfg.pki_dir / "private",
        cfg.pki_dir / "reqs",
        cfg.ccd_dir,
        cfg.log_dir,
        run_dir,
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Management/OAuth2 unix sockets live here - root-only so no other
    # in-container user can drive the unauthenticated management API.
    run_dir.chmod(0o700)


def setup_log_rotation() -> None:
    """Configure logrotate for OpenVPN logs."""
    logger.info("Configuring log rotation...")

    logrotate_conf = Path("/etc/logrotate.d/vpn")
    logrotate_conf.write_text(
        """
/var/log/vpn/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    missingok
    create 0640 nobody nogroup
}
""".strip()
    )

    logger.info("Log rotation configured (daily, 7 days retention)")


def setup_scripts(cfg) -> None:
    """Make operator-supplied client-connect hooks executable.

    Culvert ships no hook scripts. This exists for the operator who mounts their
    own at the documented paths, so they do not have to get the mode right in
    their image or volume as well as uncommenting the server config lines.
    """
    scripts = [
        cfg.scripts_dir / "client-connect.sh",
        cfg.scripts_dir / "client-disconnect.sh",
    ]

    for script in scripts:
        if script.exists():
            script.chmod(0o755)
            logger.info(f"Made hook script executable: {script}")


class ProcessManager:
    """Manages VPN child processes with proper signal handling."""

    def __init__(self):
        self.processes: dict[str, subprocess.Popen] = {}
        self.shutdown_requested = False
        self.config = None
        self._daemon_logs: dict[str, BinaryIO] = {}
        self._setup_signal_handlers()

    def _setup_signal_handlers(self) -> None:
        """Setup handlers for SIGTERM and SIGINT."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._reload_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name
        logger.info(
            f"Received {sig_name}, initiating graceful shutdown...",
            signal=sig_name,
        )
        self.shutdown_requested = True
        self.shutdown()

    def _reload_handler(self, signum: int, frame) -> None:
        """Handle SIGHUP for config reload."""
        logger.info("Received SIGHUP, signaling OpenVPN processes to reload...")
        for name, proc in self.processes.items():
            if proc.poll() is None:
                logger.info(f"Sending SIGHUP to {name}", pid=proc.pid)
                proc.send_signal(signal.SIGHUP)

    def start(
        self, name: str, cmd: list[str], daemon: bool = False
    ) -> subprocess.Popen | None:
        """Start a process and track it.

        Daemon output goes to an append-mode log file, never a PIPE: an
        unread PIPE fills its 64K buffer and then blocks the child on
        write (a busy oauth2/wstunnel daemon would stall mid-connection).
        """
        logger.info(f"Starting {name}...", command=" ".join(cmd))
        stdout = stderr = None
        if daemon:
            log_dir = self.config.log_dir if self.config else Path("/var/log/vpn")
            try:
                log_f = (Path(log_dir) / f"{name}.log").open("ab")
                os.fchmod(log_f.fileno(), 0o640)
                self._daemon_logs[name] = log_f
                stdout = log_f
                stderr = subprocess.STDOUT
            except OSError:
                stdout = subprocess.DEVNULL
                stderr = subprocess.DEVNULL
        try:
            proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
            self.processes[name] = proc
            logger.info(f"{name} started", pid=proc.pid)
            return proc
        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            return None

    def shutdown(self, exit_code: int = 0) -> None:
        """Gracefully shutdown all processes and exit with exit_code.

        Callers pass a non-zero code when the main VPN process died
        unexpectedly, so PID 1 reports failure and restart policies
        like on-failure actually fire.
        """
        # Clear readiness immediately so K8s stops routing traffic
        from lib.health import health

        health.set_ready(False)
        logger.info("Shutting down all VPN processes...")

        # Shut down WireGuard interface if active
        if self.config and self.config.protocol in (
            "wireguard",
            "both",
        ):
            logger.info("Shutting down WireGuard")
            subprocess.run(
                ["wg-quick", "down", str(self.config.wg_conf)],
                check=False,
            )

        # Send SIGTERM to all processes
        for name, proc in self.processes.items():
            if proc.poll() is None:
                logger.info(f"Sending SIGTERM to {name}", pid=proc.pid)
                proc.terminate()

        # Wait for processes to exit (with timeout)
        for name, proc in self.processes.items():
            try:
                proc.wait(timeout=10)
                logger.info(
                    f"{name} stopped",
                    pid=proc.pid,
                    returncode=proc.returncode,
                )
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"{name} did not stop gracefully, sending SIGKILL",
                    pid=proc.pid,
                )
                proc.kill()
                proc.wait()

        for log_f in self._daemon_logs.values():
            try:
                log_f.close()
            except OSError:
                pass
        logger.info("All processes stopped")
        sys.exit(exit_code)

    def wait_for_main(self, name: str) -> int:
        """Wait for main process to exit."""
        proc = self.processes.get(name)
        if not proc:
            return 1
        try:
            return proc.wait()
        except KeyboardInterrupt:
            self.shutdown()
            return 0
