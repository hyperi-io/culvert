#  Project:      culvert
#  File:         management.py
#  Purpose:      End a revoked client's live sessions over the OpenVPN management sockets
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""OpenVPN management interface client, for ending a client's live sessions.

A revoked certificate is refused at the next TLS handshake, which for a session
already up is the next renegotiation. Sending `kill <cn>` on each listener's
management socket ends it now.
"""

import socket
from collections.abc import Iterator
from pathlib import Path

from scalo.logger import logger

from lib.pki import validate_client_name

RUN_DIR = Path("/run/vpn")
PASSWORD_FILE = Path("/etc/vpn/management.pwd")
TIMEOUT_SECONDS = 5.0

_PASSWORD_PROMPT = b"ENTER PASSWORD:"


class ManagementError(RuntimeError):
    """A management socket answered, but not with a usable result."""


def _lines(sock: socket.socket) -> Iterator[str]:
    """Yield what the server sends, one line at a time.

    The password prompt carries no newline, so it is yielded as its own line.
    """
    buf = b""
    while True:
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode("utf-8", errors="replace").strip()
        if buf.startswith(_PASSWORD_PROMPT):
            buf = buf[len(_PASSWORD_PROMPT) :]
            yield _PASSWORD_PROMPT.decode()
            continue
        chunk = sock.recv(4096)
        if not chunk:
            return
        buf += chunk


def _kill_on(socket_path: Path, client_name: str, password: str, timeout: float) -> str:
    """Send `kill <client_name>` on one management socket and return the reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
        asked = False
        for line in _lines(sock):
            if line == _PASSWORD_PROMPT.decode():
                if not password:
                    raise ManagementError("it wants a password and none is available")
                sock.sendall(password.encode() + b"\n")
            elif line.startswith(">INFO") and not asked:
                sock.sendall(f"kill {client_name}\n".encode())
                asked = True
            elif line.startswith(("SUCCESS:", "ERROR:")):
                if asked:
                    sock.sendall(b"quit\n")
                    return line
                if line.startswith("ERROR:"):
                    raise ManagementError("it refused the password")
        raise ManagementError("it closed the connection without a reply")


def kill_client_sessions(
    client_name: str,
    run_dir: Path = RUN_DIR,
    password_file: Path = PASSWORD_FILE,
    timeout: float = TIMEOUT_SECONDS,
) -> int:
    """End the client's live sessions on every listener, and return how many sockets held one.

    A socket that is missing, silent or refusing is a warning and never an
    error: the CRL already blocks the client's next handshake. The management
    password, read from password_file when a socket asks for one, is never logged.
    """
    if not validate_client_name(client_name):
        raise ValueError(f"not a client name: {client_name!r}")

    password = ""
    if password_file.exists():
        password = password_file.read_text(encoding="utf-8").strip()

    killed = 0
    for socket_path in sorted(run_dir.glob("management-*.sock")):
        try:
            reply = _kill_on(socket_path, client_name, password, timeout)
        except (OSError, ManagementError) as exc:
            logger.warning(
                f"Could not end live sessions on {socket_path.name}: {exc}."
                " The CRL still refuses the client's next handshake.",
            )
            continue
        if reply.startswith("SUCCESS:"):
            killed += 1
            logger.info(f"Ended live sessions on {socket_path.name}: {reply}")
        else:
            logger.debug(f"No live session on {socket_path.name}: {reply}")
    return killed
