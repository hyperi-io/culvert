#  Project:      culvert
#  File:         test_network.py
#  Purpose:      Tests for network utilities module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import pytest
from lib.network import cidr_to_netmask


class TestCidrToNetmask:
    """Tests for CIDR prefix to netmask conversion."""

    def test_24_prefix(self):
        assert cidr_to_netmask(24) == "255.255.255.0"

    def test_16_prefix(self):
        assert cidr_to_netmask(16) == "255.255.0.0"

    def test_8_prefix(self):
        assert cidr_to_netmask(8) == "255.0.0.0"

    def test_32_prefix(self):
        assert cidr_to_netmask(32) == "255.255.255.255"

    def test_0_prefix(self):
        assert cidr_to_netmask(0) == "0.0.0.0"

    def test_28_prefix(self):
        assert cidr_to_netmask(28) == "255.255.255.240"

    def test_25_prefix(self):
        assert cidr_to_netmask(25) == "255.255.255.128"

    def test_20_prefix(self):
        assert cidr_to_netmask(20) == "255.255.240.0"

    def test_invalid_prefix_raises(self):
        """Prefix > 32 raises ValueError."""
        with pytest.raises(ValueError):
            cidr_to_netmask(33)

    def test_negative_prefix_raises(self):
        """Negative prefix raises ValueError."""
        with pytest.raises(ValueError):
            cidr_to_netmask(-1)
