#  Project:      culvert
#  File:         test_network.py
#  Purpose:      Tests for network utilities module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import pytest
from lib import network
from lib.network import (
    _csv_cidrs,
    _prefixlen,
    _vpn_interfaces,
    cidr_to_netmask,
    setup_routing_control,
)


class FakeCfg:
    """Minimal cfg carrying the routing-control fields."""

    def __init__(
        self,
        protocol="openvpn",
        routing_control_enabled=True,
        client_isolation=True,
        allowed_destinations="",
        downstream_admin_cidrs="",
    ):
        self.protocol = protocol
        self.routing_control_enabled = routing_control_enabled
        self.client_isolation = client_isolation
        self.allowed_destinations = allowed_destinations
        self.downstream_admin_cidrs = downstream_admin_cidrs


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


class TestPrefixlen:
    """Netmask -> prefix length derivation used by the NAT rules."""

    def test_slash_24(self):
        assert _prefixlen("10.8.0.0", "255.255.255.0") == 24

    def test_slash_16(self):
        assert _prefixlen("10.8.0.0", "255.255.0.0") == 16

    def test_slash_20(self):
        assert _prefixlen("10.8.0.0", "255.255.240.0") == 20


class TestCsvCidrs:
    def test_empty(self):
        assert _csv_cidrs("") == []

    def test_spaces_and_blanks(self):
        assert _csv_cidrs(" 10.0.0.0/8 ,, 172.16.0.0/12 ") == [
            "10.0.0.0/8",
            "172.16.0.0/12",
        ]


class TestVpnInterfaces:
    def test_openvpn(self):
        assert _vpn_interfaces(FakeCfg(protocol="openvpn")) == ["tun+"]

    def test_wireguard(self):
        assert _vpn_interfaces(FakeCfg(protocol="wireguard")) == ["wg0"]

    def test_both(self):
        assert _vpn_interfaces(FakeCfg(protocol="both")) == ["tun+", "wg0"]


class FakeNatCfg:
    """Minimal cfg carrying the fields setup_network masquerades on."""

    def __init__(self, protocol="openvpn"):
        self.protocol = protocol
        self.udp_enabled = True
        self.udp_network = "10.8.0.0"
        self.udp_netmask = "255.255.255.0"
        self.https_enabled = False
        self.https_network = "10.8.2.0"
        self.https_netmask = "255.255.255.0"
        self.tcp_enabled = False
        self.tcp_network = "10.8.1.0"
        self.tcp_netmask = "255.255.255.0"
        self.wg_network = "10.8.3.0/24"


class TestNatRules:
    """Every tunnel subnet that carries clients has to be masqueraded.

    A missing rule is invisible at connect time: the client gets an address and
    a handshake, and only then finds it can reach nothing.
    """

    def _capture(self, monkeypatch):
        calls = []

        class FakeResult:
            stdout = "eth0\n"

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return FakeResult()

        monkeypatch.setattr(network, "run", fake_run)
        return calls

    def test_openvpn_only_does_not_masquerade_wireguard(self, monkeypatch):
        calls = self._capture(monkeypatch)
        network.setup_network(FakeNatCfg(protocol="openvpn"))
        assert not any("10.8.3.0/24" in c for c in calls)

    @pytest.mark.parametrize("protocol", ["wireguard", "both"])
    def test_wireguard_subnet_is_masqueraded(self, monkeypatch, protocol):
        calls = self._capture(monkeypatch)
        network.setup_network(FakeNatCfg(protocol=protocol))
        assert any(
            "-t nat -A POSTROUTING -s 10.8.3.0/24" in c and "MASQUERADE" in c
            for c in calls
        ), f"no MASQUERADE for the WireGuard subnet with protocol={protocol}: {calls}"

    def test_openvpn_udp_subnet_is_masqueraded(self, monkeypatch):
        calls = self._capture(monkeypatch)
        network.setup_network(FakeNatCfg(protocol="both"))
        assert any(
            "-t nat -A POSTROUTING -s 10.8.0.0/24" in c and "MASQUERADE" in c
            for c in calls
        )


class TestRoutingControl:
    """FORWARD-chain rule generation (run() captured, not executed)."""

    def _capture(self, monkeypatch):
        calls = []
        monkeypatch.setattr(network, "run", lambda cmd, **kw: calls.append(cmd))
        return calls

    def test_disabled_emits_nothing(self, monkeypatch):
        calls = self._capture(monkeypatch)
        setup_routing_control(FakeCfg(routing_control_enabled=False))
        assert calls == []

    def test_chain_setup_and_isolation(self, monkeypatch):
        calls = self._capture(monkeypatch)
        setup_routing_control(FakeCfg(protocol="openvpn"))

        assert "iptables -N CULVERT_FWD" in calls
        # isolation: tun-to-tun dropped
        iso = "iptables -A CULVERT_FWD -i tun+ -o tun+ -j DROP"
        assert iso in calls
        # unsolicited inbound to tunnels denied
        deny = "iptables -A CULVERT_FWD -o tun+ -j DROP"
        assert deny in calls
        ct_idx = next(i for i, c in enumerate(calls) if "conntrack" in c)
        # isolation is decided BEFORE conntrack (state-independent)
        assert calls.index(iso) < ct_idx
        # the default-deny into tunnels comes AFTER conntrack
        assert ct_idx < calls.index(deny)
        # the FORWARD jump is inserted LAST, after all chain rules
        jump_idx = calls.index("iptables -I FORWARD 1 -j CULVERT_FWD")
        last_rule = max(
            i for i, c in enumerate(calls) if c.startswith("iptables -A CULVERT_FWD")
        )
        assert jump_idx > last_rule
        # no egress restriction rules when allowed_destinations empty
        assert not any("-d " in c for c in calls)

    def test_isolation_can_be_disabled(self, monkeypatch):
        calls = self._capture(monkeypatch)
        setup_routing_control(FakeCfg(client_isolation=False))
        assert "iptables -A CULVERT_FWD -i tun+ -o tun+ -j DROP" not in calls
        # isolation off must EXPLICITLY permit client-to-client, else the
        # default-deny into tunnels would drop it anyway
        assert "iptables -A CULVERT_FWD -i tun+ -o tun+ -j ACCEPT" in calls

    def test_admin_cidrs_punch_holes_before_deny(self, monkeypatch):
        calls = self._capture(monkeypatch)
        setup_routing_control(
            FakeCfg(protocol="both", downstream_admin_cidrs="10.10.0.0/16")
        )
        accept = "iptables -A CULVERT_FWD -o tun+ -s 10.10.0.0/16 -j ACCEPT"
        deny = "iptables -A CULVERT_FWD -o tun+ -j DROP"
        assert accept in calls
        assert deny in calls
        assert calls.index(accept) < calls.index(deny)
        # wg0 gets the same treatment
        assert "iptables -A CULVERT_FWD -o wg0 -s 10.10.0.0/16 -j ACCEPT" in calls
        assert "iptables -A CULVERT_FWD -o wg0 -j DROP" in calls
        # reverse-admin REPLIES (established) excluded from NAT so they keep
        # their real tunnel source (inserted at POSTROUTING position 1); a
        # client INITIATING to the admin CIDR is still masqueraded
        assert (
            "iptables -t nat -I POSTROUTING 1 -m conntrack"
            " --ctstate ESTABLISHED,RELATED -d 10.10.0.0/16 -j RETURN" in calls
        )

    def test_no_nat_exclusion_without_admin_cidrs(self, monkeypatch):
        calls = self._capture(monkeypatch)
        setup_routing_control(FakeCfg())
        assert not any("-j RETURN" in c for c in calls)

    def test_egress_allowlist_terminal_drop(self, monkeypatch):
        calls = self._capture(monkeypatch)
        setup_routing_control(
            FakeCfg(allowed_destinations="100.96.0.0/16, 10.20.0.0/24")
        )
        a1 = "iptables -A CULVERT_FWD -i tun+ -d 100.96.0.0/16 -j ACCEPT"
        a2 = "iptables -A CULVERT_FWD -i tun+ -d 10.20.0.0/24 -j ACCEPT"
        drop = "iptables -A CULVERT_FWD -i tun+ -j DROP"
        assert a1 in calls
        assert a2 in calls
        assert drop in calls
        assert calls.index(a1) < calls.index(drop)
        assert calls.index(a2) < calls.index(drop)
