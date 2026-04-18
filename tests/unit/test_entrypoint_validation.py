#  Project:      hyperi-vpn
#  File:         test_entrypoint_validation.py
#  Purpose:      Test entrypoint input validation
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for entrypoint.py validation functions."""

import pytest
from lib.config import (
    ValidationError,
    validate_bool,
    validate_cidr_routes,
    validate_hostname,
    validate_ipv4,
    validate_port,
    validate_url,
)


class TestValidateIPv4:
    """Tests for IPv4 address validation."""

    def test_valid_ipv4(self):
        """Valid IPv4 addresses pass validation."""
        valid_ips = ["1.1.1.1", "192.168.1.1", "10.0.0.1", "255.255.255.255"]
        for ip in valid_ips:
            validate_ipv4(ip, "TEST_IP")  # Should not raise

    def test_invalid_ipv4(self):
        """Invalid IPv4 addresses raise ValidationError."""
        invalid_ips = ["256.1.1.1", "1.2.3", "not.an.ip", "1.2.3.4.5"]
        for ip in invalid_ips:
            with pytest.raises(ValidationError):
                validate_ipv4(ip, "TEST_IP")

    def test_empty_ipv4_allowed(self):
        """Empty string is allowed (optional field)."""
        validate_ipv4("", "TEST_IP")  # Should not raise


class TestValidatePort:
    """Tests for port number validation."""

    def test_valid_ports(self):
        """Valid port numbers pass validation."""
        valid_ports = [1, 80, 443, 1194, 65535]
        for port in valid_ports:
            validate_port(port, "TEST_PORT")  # Should not raise

    def test_port_zero_invalid(self):
        """Port 0 is invalid."""
        with pytest.raises(ValidationError):
            validate_port(0, "TEST_PORT")

    def test_negative_port_invalid(self):
        """Negative port numbers are invalid."""
        with pytest.raises(ValidationError):
            validate_port(-1, "TEST_PORT")

    def test_port_above_65535_invalid(self):
        """Port numbers above 65535 are invalid."""
        with pytest.raises(ValidationError):
            validate_port(65536, "TEST_PORT")


class TestValidateBool:
    """Tests for boolean value validation."""

    def test_valid_bool_values(self):
        """Valid boolean strings pass validation."""
        valid_values = ["true", "false", "1", "0", "yes", "no"]
        for val in valid_values:
            validate_bool(val, "TEST_BOOL")  # Should not raise

    def test_invalid_bool_values(self):
        """Invalid boolean strings raise ValidationError."""
        invalid_values = ["maybe", "2", "enabled", "disabled"]
        for val in invalid_values:
            with pytest.raises(ValidationError):
                validate_bool(val, "TEST_BOOL")

    def test_empty_bool_allowed(self):
        """Empty string is allowed (not set)."""
        validate_bool("", "TEST_BOOL")  # Should not raise


class TestValidateHostname:
    """Tests for hostname/FQDN validation."""

    def test_valid_hostnames(self):
        """Valid hostnames pass validation."""
        valid_hostnames = [
            "localhost",
            "example.com",
            "vpn.example.com",
            "my-host.example.co.uk",
            "host123.test.com",
        ]
        for hostname in valid_hostnames:
            validate_hostname(hostname, "TEST_HOSTNAME")  # Should not raise

    def test_invalid_hostnames(self):
        """Invalid hostnames raise ValidationError."""
        invalid_hostnames = [
            "",
            "-invalid.com",
            "invalid-.com",
            "inva lid.com",
            ".startwithdot.com",
        ]
        for hostname in invalid_hostnames:
            with pytest.raises(ValidationError):
                validate_hostname(hostname, "TEST_HOSTNAME")


class TestValidateUrl:
    """Tests for URL validation."""

    def test_valid_urls(self):
        """Valid URLs pass validation."""
        valid_urls = [
            "http://example.com",
            "https://example.com",
            "https://example.com/path",
            "https://login.microsoftonline.com/tenant/v2.0",
        ]
        for url in valid_urls:
            validate_url(url, "TEST_URL")  # Should not raise

    def test_invalid_urls(self):
        """Invalid URLs raise ValidationError."""
        invalid_urls = [
            "ftp://example.com",
            "example.com",
            "//example.com",
            "not a url",
        ]
        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_url(url, "TEST_URL")


class TestValidateCidrRoutes:
    """Tests for CIDR route validation."""

    def test_valid_cidr_routes(self):
        """Valid CIDR routes pass validation."""
        valid_routes = [
            "10.0.0.0/8",
            "192.168.1.0/24",
            "10.0.0.0/16,172.16.0.0/12",
            "192.168.100.0/24, 10.0.0.0/8",  # With spaces
        ]
        for routes in valid_routes:
            validate_cidr_routes(routes, "TEST_ROUTES")  # Should not raise

    def test_invalid_cidr_routes(self):
        """Invalid CIDR routes raise ValidationError."""
        # Note: "10.0.0.0" without prefix is valid (becomes /32)
        invalid_routes = [
            "10.0.0.0/33",  # Invalid prefix (> 32)
            "256.0.0.0/8",  # Invalid IP
            "not-a-cidr",
        ]
        for routes in invalid_routes:
            with pytest.raises(ValidationError):
                validate_cidr_routes(routes, "TEST_ROUTES")

    def test_empty_cidr_allowed(self):
        """Empty string is allowed (no routes)."""
        validate_cidr_routes("", "TEST_ROUTES")  # Should not raise
