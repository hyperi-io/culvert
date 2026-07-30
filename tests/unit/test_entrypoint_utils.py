#  Project:      culvert
#  File:         test_entrypoint_utils.py
#  Purpose:      Test entrypoint utility functions
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for entrypoint.py utility functions."""

from lib.network import cidr_to_netmask
from lib.openvpn import _strip_timestamps


class TestCidrToNetmask:
    """Tests for CIDR prefix to netmask conversion."""

    def test_cidr_32(self):
        """/32 returns 255.255.255.255."""
        assert cidr_to_netmask(32) == "255.255.255.255"

    def test_cidr_24(self):
        """/24 returns 255.255.255.0."""
        assert cidr_to_netmask(24) == "255.255.255.0"

    def test_cidr_16(self):
        """/16 returns 255.255.0.0."""
        assert cidr_to_netmask(16) == "255.255.0.0"

    def test_cidr_8(self):
        """/8 returns 255.0.0.0."""
        assert cidr_to_netmask(8) == "255.0.0.0"

    def test_cidr_0(self):
        """/0 returns 0.0.0.0."""
        assert cidr_to_netmask(0) == "0.0.0.0"

    def test_cidr_25(self):
        """/25 returns 255.255.255.128."""
        assert cidr_to_netmask(25) == "255.255.255.128"

    def test_cidr_20(self):
        """/20 returns 255.255.240.0."""
        assert cidr_to_netmask(20) == "255.255.240.0"

    def test_cidr_12(self):
        """/12 returns 255.240.0.0."""
        assert cidr_to_netmask(12) == "255.240.0.0"


class TestStripTimestamps:
    """Tests for timestamp stripping from config content."""

    def test_strips_date_comments(self):
        """Strips comments containing dates."""
        content = """# Config file
# Generated: 2025-12-20
key=value
"""
        result = _strip_timestamps(content)
        assert "2025-12-20" not in result
        assert "key=value" in result

    def test_strips_culvert_version_comments(self):
        """Strips Culvert version comments."""
        content = """# Culvert 1.2.3
key=value
"""
        result = _strip_timestamps(content)
        assert "Culvert 1.2.3" not in result
        assert "key=value" in result

    def test_preserves_other_comments(self):
        """Preserves comments without timestamps."""
        content = """# Configuration comment
key=value
# Another comment
"""
        result = _strip_timestamps(content)
        assert "Configuration comment" in result
        assert "key=value" in result
