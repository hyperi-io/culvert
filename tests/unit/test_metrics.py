#  Project:      hyperi-vpn
#  File:         test_metrics.py
#  Purpose:      Tests for metrics module parsing functions
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED


from lib.metrics import (
    collect_openvpn_status,
    parse_openvpn_status_v3,
    parse_wg_handshakes,
    parse_wg_transfer,
)


class TestParseOpenVPNStatusV3:
    """Tests for OpenVPN status-version 3 parser."""

    def test_counts_clients(self):
        """Parse status file and count clients."""
        status = (
            "TITLE\ttab\n"
            "TIME\t2026-04-01 12:00:00\n"
            "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\t"
            "Virtual Address\tVirtual IPv6 Address\t"
            "Bytes Received\tBytes Sent\tConnected Since\n"
            "CLIENT_LIST\talice\t1.2.3.4:1194\t192.168.100.2\t\t"
            "1024\t2048\t2026-04-01 11:00:00\n"
            "CLIENT_LIST\tbob\t5.6.7.8:1194\t192.168.100.3\t\t"
            "512\t1024\t2026-04-01 11:30:00\n"
            "END\n"
        )
        result = parse_openvpn_status_v3(status)
        assert result.client_count == 2
        assert result.bytes_received == 1536
        assert result.bytes_sent == 3072

    def test_empty_status_file(self):
        """Empty status file returns zero counts."""
        result = parse_openvpn_status_v3("TITLE\ttab\nEND\n")
        assert result.client_count == 0
        assert result.bytes_received == 0
        assert result.bytes_sent == 0

    def test_single_client(self):
        """Status file with one client."""
        status = (
            "CLIENT_LIST\tuser1\t10.0.0.1:5000\t192.168.100.2\t\t"
            "999\t888\t2026-04-01 12:00:00\n"
        )
        result = parse_openvpn_status_v3(status)
        assert result.client_count == 1
        assert result.bytes_received == 999
        assert result.bytes_sent == 888
        assert result.clients[0]["common_name"] == "user1"
        assert result.clients[0]["real_address"] == "10.0.0.1:5000"
        assert result.clients[0]["virtual_address"] == "192.168.100.2"

    def test_ignores_non_client_lines(self):
        """Parser ignores HEADER, TITLE, ROUTING_TABLE lines."""
        status = (
            "TITLE\tOpenVPN\n"
            "TIME\t2026-04-01\n"
            "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\t"
            "Virtual Address\tVirtual IPv6 Address\t"
            "Bytes Received\tBytes Sent\tConnected Since\n"
            "CLIENT_LIST\talice\t1.2.3.4:1194\t10.0.0.2\t\t"
            "100\t200\t2026-04-01\n"
            "HEADER\tROUTING_TABLE\n"
            "ROUTING_TABLE\t10.0.0.2\talice\t1.2.3.4:1194\n"
            "GLOBAL_STATS\tMax bcast/mcast queue length\t0\n"
            "END\n"
        )
        result = parse_openvpn_status_v3(status)
        assert result.client_count == 1

    def test_malformed_line_still_counted(self):
        """Lines with too few fields are counted but fields not parsed."""
        status = (
            "CLIENT_LIST\tshort_line\n"
            "CLIENT_LIST\tvalid\t1.2.3.4:1194\t10.0.0.2\t\t"
            "100\t200\t2026-04-01\n"
        )
        result = parse_openvpn_status_v3(status)
        # Both lines counted (non-fragile), but only the valid one has fields
        assert result.client_count == 2
        assert len(result.clients) == 1

    def test_many_clients(self):
        """Status file with many clients sums correctly."""
        lines = []
        for i in range(50):
            lines.append(
                f"CLIENT_LIST\tuser{i}\t10.0.0.{i}:1194\t"
                f"192.168.100.{i + 2}\t\t"
                f"{(i + 1) * 100}\t{(i + 1) * 200}\t2026-04-01\n"
            )
        status = "".join(lines)
        result = parse_openvpn_status_v3(status)
        assert result.client_count == 50
        assert result.bytes_received == sum((i + 1) * 100 for i in range(50))


class TestParseWgTransfer:
    """Tests for WireGuard transfer output parser."""

    def test_parses_two_peers(self):
        """Parse wg show transfer with two peers."""
        output = "abc123pubkey=\t1024\t2048\ndef456pubkey=\t512\t1024\n"
        peers = parse_wg_transfer(output)
        assert len(peers) == 2
        assert peers["abc123pubkey="].rx == 1024
        assert peers["abc123pubkey="].tx == 2048
        assert peers["def456pubkey="].rx == 512
        assert peers["def456pubkey="].tx == 1024

    def test_empty_output(self):
        """Empty output returns no peers."""
        assert parse_wg_transfer("") == {}

    def test_single_peer(self):
        """Single peer parses correctly."""
        output = "peerkey123=\t0\t0\n"
        peers = parse_wg_transfer(output)
        assert len(peers) == 1
        assert peers["peerkey123="].rx == 0
        assert peers["peerkey123="].tx == 0

    def test_large_transfer_values(self):
        """Large byte values parse correctly."""
        output = "key=\t99999999999\t88888888888\n"
        peers = parse_wg_transfer(output)
        assert peers["key="].rx == 99999999999
        assert peers["key="].tx == 88888888888

    def test_ignores_blank_lines(self):
        """Blank lines between entries are ignored."""
        output = "key1=\t100\t200\n\n\nkey2=\t300\t400\n"
        peers = parse_wg_transfer(output)
        assert len(peers) == 2


class TestParseWgHandshakes:
    """Tests for WireGuard handshake output parser."""

    def test_parses_handshakes(self):
        """Parse wg show latest-handshakes."""
        output = "abc123pubkey=\t1711929600\ndef456pubkey=\t1711929900\n"
        peers = parse_wg_handshakes(output)
        assert len(peers) == 2
        assert peers["abc123pubkey="].timestamp == 1711929600
        assert peers["def456pubkey="].timestamp == 1711929900

    def test_empty_output(self):
        """Empty output returns no peers."""
        assert parse_wg_handshakes("") == {}

    def test_zero_timestamp_means_never(self):
        """Timestamp of 0 means no handshake yet."""
        output = "key=\t0\n"
        peers = parse_wg_handshakes(output)
        assert peers["key="].timestamp == 0


class TestCollectOpenVPNStatus:
    """Tests for status file collection."""

    def test_reads_existing_file(self, tmp_path):
        """Reads and parses an existing status file."""
        status_file = tmp_path / "status.log"
        status_file.write_text(
            "CLIENT_LIST\tuser1\t1.2.3.4:1194\t10.0.0.2\t\t100\t200\t2026-04-01\n"
        )
        result = collect_openvpn_status(str(status_file), "udp")
        assert result is not None
        assert result.client_count == 1

    def test_returns_none_for_missing_file(self):
        """Returns None when status file doesn't exist."""
        result = collect_openvpn_status("/nonexistent/status.log", "udp")
        assert result is None


class TestBuildPubkeyToName:
    """Tests for WireGuard pubkey-to-name mapping."""

    def test_maps_pubkeys_to_names(self, tmp_path):
        """Reads .pub files and builds pubkey->name mapping."""
        from lib.wireguard import _build_pubkey_to_name

        peers_dir = tmp_path / "wireguard" / "peers"
        peers_dir.mkdir(parents=True)
        (peers_dir / "alice.pub").write_text("AAAA1234=\n")
        (peers_dir / "bob.pub").write_text("BBBB5678=\n")

        mapping = _build_pubkey_to_name(tmp_path)
        assert mapping == {
            "AAAA1234=": "alice",
            "BBBB5678=": "bob",
        }

    def test_empty_peers_dir(self, tmp_path):
        """Empty peers dir returns empty mapping."""
        from lib.wireguard import _build_pubkey_to_name

        peers_dir = tmp_path / "wireguard" / "peers"
        peers_dir.mkdir(parents=True)

        assert _build_pubkey_to_name(tmp_path) == {}

    def test_missing_peers_dir(self, tmp_path):
        """Missing peers dir returns empty mapping."""
        from lib.wireguard import _build_pubkey_to_name

        assert _build_pubkey_to_name(tmp_path) == {}
