#  Project:      culvert
#  File:         test_entrypoint_utils.py
#  Purpose:      Test entrypoint utility functions
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for entrypoint.py utility functions."""

from lib.openvpn import _strip_timestamps


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
