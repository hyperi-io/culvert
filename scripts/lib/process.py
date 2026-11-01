#  Project:      culvert
#  File:         process.py
#  Purpose:      Process management, signal handling, and shell command helpers
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Process management for culvert container.

Provides ProcessManager for supervised child processes with graceful
shutdown, plus the run() shell command helper and directory/
log rotation setup functions.
"""

import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import BinaryIO

from scalo.logger import logger

# Inside the deployment contract's 30 s termination grace period: the drain
# (CULVERT_DRAIN_SECONDS, 10 by default) and then this long for children to exit.
CHILD_STOP_SECONDS = 15
DRAIN_POLL_SECONDS = 1.0

# Children with a SIGHUP reload. Any other child (wstunnel) dies of the signal.
RELOADS_ON_SIGHUP_PREFIX = "openvpn-"
RELOADS_ON_SIGHUP = frozenset({"stunnel"})


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


def write_file_atomic(path: Path, data: bytes, mode: int) -> None:
    """Replace path with data, readable only by this user until it is complete.

    The content goes to a private temp file beside path and is renamed over it, so
    a reader never sees a partial file, a private key is never wider than 0600
    while it is written, and two writers sharing the directory never share a temp
    file. The final mode is applied before the rename. The file is flushed before
    the rename and the directory after it, so a crash leaves the old file or the
    new one, never an empty one.
    """
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def snapshot_files(paths: Iterable[Path]) -> dict[Path, tuple[bytes, int] | None]:
    """Record each file's content and mode, or None where it does not exist."""
    saved: dict[Path, tuple[bytes, int] | None] = {}
    for path in paths:
        try:
            saved[path] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        except FileNotFoundError:
            saved[path] = None
    return saved


def restore_files(saved: dict[Path, tuple[bytes, int] | None]) -> None:
    """Put back every file snapshot_files recorded, and remove those it did not find."""
    for path, before in saved.items():
        if before is None:
            path.unlink(missing_ok=True)
        else:
            write_file_atomic(path, *before)


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


# logrotate rotates daily or past maxsize, so an hourly check holds the size cap.
LOG_ROTATION_INTERVAL_SECONDS = 3600


def setup_log_rotation(
    cfg, conf_path: Path = Path("/etc/logrotate.d/vpn")
) -> tuple[Path, Path]:
    """Write the logrotate config for the server's logs, returning it and its state.

    copytruncate, because OpenVPN, stunnel and the daemon logs keep an O_APPEND
    descriptor open and never reopen it. The status files are not logs: OpenVPN
    rewrites them in place every few seconds, so they are not listed.
    """
    log_dir = Path(cfg.log_dir)
    logs = " ".join(
        str(log_dir / name)
        for name in ("openvpn*.log", "stunnel.log", "wstunnel.log", "oauth2-*.log")
    )
    conf_path.write_text(
        f"""{logs} {{
    daily
    maxsize 100M
    rotate 7
    compress
    delaycompress
    copytruncate
    notifempty
    missingok
}}
"""
    )
    logger.info("Log rotation configured (daily or past 100M, 7 kept)")
    return conf_path, log_dir / "logrotate.status"


def rotate_logs(conf_path: Path, state_path: Path, force: bool = False) -> bool:
    """Run logrotate once over conf_path. True when it exited cleanly."""
    cmd = ["logrotate", "--state", str(state_path), str(conf_path)]
    if force:
        cmd.insert(1, "--force")
    try:
        result = run(cmd, check=False, capture=True)
    except FileNotFoundError:
        logger.error("logrotate is not installed, so the server logs grow unbounded")
        return False
    if result.returncode != 0:
        logger.warning(f"logrotate failed: {result.stderr.strip()}")
    return result.returncode == 0


def start_log_rotation(
    conf_path: Path,
    state_path: Path,
    interval: float = LOG_ROTATION_INTERVAL_SECONDS,
) -> None:
    """Run logrotate on a schedule in a daemon thread, since no cron runs here."""
    import threading

    def rotate_loop() -> None:
        while True:
            rotate_logs(conf_path, state_path)
            time.sleep(interval)

    threading.Thread(target=rotate_loop, daemon=True, name="logrotate").start()


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


def connected_clients() -> int:
    """Count OpenVPN sessions in the status files and recently active WireGuard peers."""
    from lib.metrics import (
        OPENVPN_STATUS_FILES,
        collect_openvpn_status,
        parse_wg_handshakes,
    )
    from lib.wireguard import PEER_ACTIVE_SECONDS

    total = 0
    for path, listener in OPENVPN_STATUS_FILES.items():
        status = collect_openvpn_status(path, listener)
        if status is not None:
            total += status.client_count
    try:
        shown = run(
            ["wg", "show", "wg0", "latest-handshakes"], check=False, capture=True
        )
    except FileNotFoundError:
        return total
    if shown.returncode == 0:
        now = time.time()
        total += sum(
            1
            for handshake in parse_wg_handshakes(shown.stdout).values()
            if handshake.timestamp and now - handshake.timestamp <= PEER_ACTIVE_SECONDS
        )
    return total


class ProcessManager:
    """Manages VPN child processes with proper signal handling."""

    def __init__(self):
        """Start with no children and install the shutdown signal handlers."""
        self.processes: dict[str, subprocess.Popen] = {}
        self.shutdown_requested = False
        self.failed_starts: dict[str, str] = {}
        self.config = None
        self.stop_timeout = CHILD_STOP_SECONDS
        self._daemon_logs: dict[str, BinaryIO] = {}
        self._setup_signal_handlers()

    def _setup_signal_handlers(self) -> None:
        """Install handlers for SIGTERM and SIGINT."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._reload_handler)

    def _signal_handler(
        self,
        signum: int,
        frame,  # noqa: V107 - signal.signal passes the frame
        count_connected: Callable[[], int] | None = None,
    ) -> None:
        """Drain, then shut down. A second signal skips what is left of the drain."""
        sig_name = signal.Signals(signum).name
        if self.shutdown_requested:
            logger.info(f"Received {sig_name} again, stopping now", signal=sig_name)
            self.shutdown()
        logger.info(f"Received {sig_name}, draining before shutdown", signal=sig_name)
        self.shutdown_requested = True
        self.drain(count_connected or connected_clients)
        self.shutdown()

    def drain(self, count_connected: Callable[[], int]) -> None:
        """Drop readiness, then serve connected clients for drain_seconds.

        The wait is for load balancers to see readiness drop and send new
        clients elsewhere. It ends early once no client is connected.
        """
        from lib.health import health

        health.set_ready(False)
        seconds = getattr(self.config, "drain_seconds", 0)
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            connected = count_connected()
            if connected == 0:
                logger.info("No clients connected, drain finished")
                return
            logger.info("Draining", clients=connected, seconds_left=round(remaining))
            time.sleep(min(DRAIN_POLL_SECONDS, remaining))
        logger.info("Drain period over")

    def _reload_handler(self, signum: int, frame) -> None:  # noqa: V107 - signal.signal passes the frame
        """Handle SIGHUP for config reload."""
        logger.info("Received SIGHUP, signaling OpenVPN processes to reload...")
        for name, proc in self.processes.items():
            if name not in RELOADS_ON_SIGHUP and not name.startswith(
                RELOADS_ON_SIGHUP_PREFIX
            ):
                continue
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
            self.failed_starts.pop(name, None)
            logger.info(f"{name} started", pid=proc.pid)
            return proc
        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            self.failed_starts[name] = str(e)
            return None

    def unhealthy(self) -> list[str]:
        """Names of children that failed to start or have since exited, sorted.

        Liveness and readiness read this, so one dead child fails the pod instead
        of hiding behind the processes that are still running.
        """
        exited = {n for n, p in self.processes.items() if p.poll() is not None}
        return sorted(exited | self.failed_starts.keys())

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

        # One deadline for all of them: per-child timeouts add up past the
        # orchestrator's termination grace period.
        deadline = time.monotonic() + self.stop_timeout
        for name, proc in self.processes.items():
            try:
                proc.wait(timeout=max(0.0, deadline - time.monotonic()))
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
