#  Project:      culvert
#  File:         test_management.py
#  Purpose:      Tests for ending a revoked client's live OpenVPN sessions
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import io
import socket

import pytest
from lib.management import kill_client_sessions
from scalo.logger import logger


@pytest.fixture
def logged():
    """Everything logged at DEBUG during the test."""
    sink = io.StringIO()
    sink_id = logger.add(sink, level="DEBUG")
    yield sink
    logger.remove(sink_id)


class TestKillClientSessions:
    def test_sends_kill_on_every_listener(self, management_dir):
        servers = [management_dir.add(name) for name in ("udp", "tcp", "https")]
        assert kill_client_sessions("alice", management_dir, management_dir / "no") == 3
        assert [s.commands for s in servers] == [["kill alice", "quit"]] * 3

    def test_password_is_sent_when_asked_and_never_logged(self, management_dir, logged):
        server = management_dir.add(mode="password", password="s3cret-value")
        password_file = management_dir / "management.pwd"
        password_file.write_text("s3cret-value\n", encoding="utf-8")

        assert kill_client_sessions("alice", management_dir, password_file) == 1
        assert server.passwords == ["s3cret-value"]
        assert "s3cret-value" not in logged.getvalue()

    @pytest.mark.parametrize(
        ("mode", "warns"),
        [
            ("not-found", False),
            ("bad-password", True),
            ("silent", True),
        ],
    )
    def test_a_socket_that_cannot_help_is_not_an_error(
        self, management_dir, logged, mode, warns
    ):
        management_dir.add(mode=mode, password="x")
        assert (
            kill_client_sessions("alice", management_dir, management_dir / "no", 0.3)
            == 0
        )
        assert ("Could not end live sessions" in logged.getvalue()) is warns

    def test_a_password_wanted_but_not_available_is_a_warning(
        self, management_dir, logged
    ):
        management_dir.add(mode="password", password="x")
        assert kill_client_sessions("alice", management_dir, management_dir / "no") == 0
        assert "none is available" in logged.getvalue()

    def test_a_stale_socket_with_no_listener_is_a_warning(self, management_dir, logged):
        stale = management_dir / "management-udp.sock"
        with socket.socket(socket.AF_UNIX) as bound:
            bound.bind(str(stale))
        assert kill_client_sessions("alice", management_dir, management_dir / "no") == 0
        assert "Could not end live sessions" in logged.getvalue()

    def test_no_sockets_is_zero(self, management_dir):
        assert kill_client_sessions("alice", management_dir, management_dir / "no") == 0

    @pytest.mark.parametrize("name", ["a b", "alice\nkill bob", "", "../x"])
    def test_a_name_that_is_not_a_client_name_never_reaches_a_socket(
        self, management_dir, name
    ):
        server = management_dir.add()
        with pytest.raises(ValueError):
            kill_client_sessions(name, management_dir, management_dir / "no")
        assert server.commands == []
