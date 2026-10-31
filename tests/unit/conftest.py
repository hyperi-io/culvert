#  Project:      culvert
#  File:         conftest.py
#  Purpose:      Unit-tier fixtures shared across test modules
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit-tier fixtures shared across test modules."""

import signal
import sys
from pathlib import Path

import pytest
from lib.process import ProcessManager

# Records how lib.pki invoked it, so a test can assert the arguments and the
# environment Easy-RSA would have seen.
FAKE_EASYRSA = """
import json
import os
import sys
from pathlib import Path

command = sys.argv[1]
if os.environ.get("FAKE_EASYRSA_FAIL") == command:
    sys.exit(f"Easy-RSA error: {command} failed")
if command != "gen-crl":
    sys.exit(0)
# Easy-RSA runs under umask 077, so a crl.pem it creates is 0600.
os.umask(0o077)
record = {
    "argv": sys.argv[1:],
    "cwd": os.getcwd(),
    "easyrsa": os.environ.get("EASYRSA"),
    "pki": os.environ.get("EASYRSA_PKI"),
    "batch": os.environ.get("EASYRSA_BATCH"),
    "crl_days": os.environ.get("EASYRSA_CRL_DAYS"),
}
Path(os.environ["EASYRSA_PKI"], "crl.pem").write_text(json.dumps(record))
"""


@pytest.fixture(autouse=True)
def _no_logger_sinks(monkeypatch):
    """Stop an entry point's scalo logger setup installing sinks during a test.

    A sink bound to one test's captured stderr outlives it, and loguru reports a
    handler error when a later test logs to the closed stream.
    """
    monkeypatch.setattr("scalo.logger.setup", lambda **_kwargs: None)


@pytest.fixture
def manager():
    """A ProcessManager whose children and signal handlers are cleaned up after."""
    handled = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    saved = {sig: signal.getsignal(sig) for sig in handled}
    pm = ProcessManager()
    yield pm
    for proc in pm.processes.values():
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    for log_f in pm._daemon_logs.values():
        log_f.close()
    for sig, handler in saved.items():
        signal.signal(sig, handler)


@pytest.fixture
def easyrsa(tmp_path, monkeypatch):
    """A stand-in Easy-RSA install that lib.pki runs in place of the real one.

    Easy-RSA is not on a CI runner; the container tier covers the real one.
    """
    import lib.pki

    install = tmp_path / "easy-rsa"
    install.mkdir()
    script = install / "easyrsa"
    script.write_text(f"#!{sys.executable}\n{FAKE_EASYRSA}", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setattr(lib.pki, "EASYRSA_DIR", install)
    # An inherited EASYRSA_CRL_DAYS must not stand in for the one lib.pki passes.
    monkeypatch.delenv("EASYRSA_CRL_DAYS", raising=False)
    return install


class FakeManagement:
    """An OpenVPN management socket that records what it is sent.

    Speaks the protocol lib.management uses: an optional password prompt, the
    >INFO banner, then one reply per `kill` until `quit`.
    """

    def __init__(self, path, mode="plain", password="", on_kill=None):
        import socket
        import threading

        self.commands: list[str] = []
        self.passwords: list[str] = []
        self.mode = mode
        self.password = password
        self.on_kill = on_kill
        # The client returns before this thread records its last command.
        self.handled = threading.Event()
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(path))
        self._server.listen()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    # The client hung up first, as it does on a refused password.
                    pass
            self.handled.set()

    def _handle(self, conn) -> None:
        if self.mode == "silent":
            conn.recv(1)
            return
        reader = conn.makefile("rb")
        if self.mode in ("password", "bad-password"):
            conn.sendall(b"ENTER PASSWORD:")
            given = reader.readline().decode().strip()
            self.passwords.append(given)
            if self.mode == "bad-password" or given != self.password:
                conn.sendall(b"ERROR: bad password\r\n")
                return
            conn.sendall(b"SUCCESS: password is correct\r\n")
        conn.sendall(b">INFO:OpenVPN Management Interface Version 5\r\n")
        for raw in reader:
            command = raw.decode().strip()
            self.commands.append(command)
            if command == "quit":
                return
            if self.on_kill:
                self.on_kill()
            if self.mode == "not-found":
                conn.sendall(b"ERROR: common name 'x' not found\r\n")
            else:
                conn.sendall(b"SUCCESS: common name 'x' found, 1 client(s) killed\r\n")

    def close(self) -> None:
        self._server.close()


class ManagementDir(type(Path())):
    """A run directory that can start fake management sockets inside itself."""

    def add(self, listener="udp", **kwargs) -> FakeManagement:
        server = FakeManagement(self / f"management-{listener}.sock", **kwargs)
        self.servers.append(server)
        return server


@pytest.fixture
def management_dir():
    """A short run directory (unix socket paths are limited to about 100 bytes)."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="mg") as tmp:
        run_dir = ManagementDir(tmp)
        run_dir.servers = []
        yield run_dir
        for server in run_dir.servers:
            server.close()
