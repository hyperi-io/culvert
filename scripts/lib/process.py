#  Project:      hyperi-vpn
#  File:         process.py
#  Purpose:      Process management, signal handling, and shell command helpers
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Process management for dfe-vpn container.

Provides ProcessManager for supervised child processes with graceful
shutdown, plus run()/run_quiet() shell command helpers and directory/
log rotation setup functions.
"""

import signal
import subprocess
import sys
from pathlib import Path

from hyperi_pylib.logger import logger


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
    )


def run_quiet(cmd: str | list) -> bool:
    """Run a command and return True if successful."""
    try:
        run(cmd, check=True, capture=True)
        return True
    except subprocess.CalledProcessError:
        return False


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
    """Make helper scripts executable."""
    logger.info("Setting up helper scripts...")

    scripts = [
        cfg.scripts_dir / "client-connect.sh",
        cfg.scripts_dir / "client-disconnect.sh",
    ]

    for script in scripts:
        if script.exists():
            script.chmod(0o755)


class ProcessManager:
    """Manages VPN child processes with proper signal handling."""

    def __init__(self):
        self.processes: dict[str, subprocess.Popen] = {}
        self.shutdown_requested = False
        self.config = None
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
        """Start a process and track it."""
        logger.info(f"Starting {name}...", command=" ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE if daemon else None,
                stderr=subprocess.PIPE if daemon else None,
            )
            self.processes[name] = proc
            logger.info(f"{name} started", pid=proc.pid)
            return proc
        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            return None

    def shutdown(self) -> None:
        """Gracefully shutdown all processes."""
        # Clear readiness immediately so K8s stops routing traffic
        from lib.health import ready

        ready.clear()
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

        logger.info("All processes stopped")
        sys.exit(0)

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
