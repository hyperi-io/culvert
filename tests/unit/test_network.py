#  Project:      culvert
#  File:         test_network.py
#  Purpose:      Tests for network utilities module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import subprocess

import pytest
from lib import network
from lib.network import (
    Destination,
    _csv_cidrs,
    _prefixlen,
    _vpn_interfaces,
    parse_destination,
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
        block_link_local=True,
    ):
        self.protocol = protocol
        self.routing_control_enabled = routing_control_enabled
        self.client_isolation = client_isolation
        self.allowed_destinations = allowed_destinations
        self.downstream_admin_cidrs = downstream_admin_cidrs
        self.block_link_local = block_link_local


@pytest.mark.parametrize(
    ("netmask", "prefix"),
    [("255.255.255.0", 24), ("255.255.0.0", 16), ("255.255.240.0", 20)],
)
def test_prefixlen_follows_the_netmask(netmask, prefix):
    """Netmask -> prefix length derivation used by the NAT rules."""
    assert _prefixlen("10.8.0.0", netmask) == prefix


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("10.20.0.0/16", Destination("10.20.0.0/16")),
        (" 10.20.0.0/16 ", Destination("10.20.0.0/16")),
        ("10.20.5.0/16", Destination("10.20.0.0/16")),
        ("10.20.0.7", Destination("10.20.0.7/32")),
        ("198.19.0.0/16:8080/tcp", Destination("198.19.0.0/16", 8080, "tcp")),
        ("198.19.0.10:53/udp", Destination("198.19.0.10/32", 53, "udp")),
        ("10.0.0.0/8:65535/tcp", Destination("10.0.0.0/8", 65535, "tcp")),
    ],
)
def test_destination_forms_that_parse(entry, expected):
    """A bare CIDR means every port, and CIDR:PORT/PROTO narrows it to one."""
    assert parse_destination(entry) == expected


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("10.20.0.0/16:8080", "CIDR:PORT/PROTO"),
        ("10.20.0.0/16:8080/sctp", "CIDR:PORT/PROTO"),
        ("10.20.0.0/16:/tcp", "CIDR:PORT/PROTO"),
        ("10.20.0.0/16:0/tcp", "outside 1-65535"),
        ("10.20.0.0/16:65536/tcp", "outside 1-65535"),
        ("not-a-cidr", "IPv4 CIDR"),
        ("10.20.0.0/33", "IPv4 CIDR"),
        ("10.20.0.0/16; id", "CIDR:PORT/PROTO"),
        ("10.20.0.0/16:8080/tcp -j ACCEPT", "CIDR:PORT/PROTO"),
        ("fd00::/8", "CIDR:PORT/PROTO"),
    ],
)
def test_destination_forms_that_are_refused(entry, reason):
    """A port needs its protocol, and nothing else rides along into iptables."""
    with pytest.raises(ValueError, match=reason):
        parse_destination(entry)


@pytest.mark.parametrize(
    ("stdout", "iface"),
    [
        ("1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0\n    cache\n", "eth0"),
        ("1.1.1.1 dev ens5 src 172.31.0.9 uid 0\n    cache\n", "ens5"),
        ("", "eth0"),
        ("RTNETLINK answers: Network is unreachable\n", "eth0"),
    ],
)
def test_outbound_interface_is_the_word_after_dev(monkeypatch, stdout, iface):
    """An on-link route has no via, so the interface is found by name, not position."""

    result = subprocess.CompletedProcess(["ip"], 0, stdout=stdout)
    monkeypatch.setattr(network, "run", lambda cmd, **kw: result)
    assert network._outbound_interface() == iface


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
            stdout = "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0\n    cache\n"

        def fake_run(cmd, **kw):
            calls.append(" ".join(cmd))
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

    @pytest.mark.parametrize("protocol", ["openvpn", "wireguard", "both"])
    def test_forwarded_tcp_is_mss_clamped(self, monkeypatch, protocol):
        """Without this a session establishes and then hangs mid-transfer.

        Every protocol needs it: the tunnel MTU is smaller than the networks on
        both sides regardless of which listener carried the client.
        """
        calls = self._capture(monkeypatch)
        network.setup_network(FakeNatCfg(protocol=protocol))
        assert any(
            "-t mangle -A FORWARD" in c and "TCPMSS --clamp-mss-to-pmtu" in c
            for c in calls
        ), f"no MSS clamp with protocol={protocol}: {calls}"


class TestRoutingControl:
    """FORWARD-chain rule generation (run() captured, not executed)."""

    def _capture(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            network, "run", lambda cmd, **kw: calls.append(" ".join(cmd))
        )
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
        # their real tunnel source (inserted at POSTROUTING position 1), and a
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

    def test_a_port_entry_opens_that_port_alone(self, monkeypatch):
        """The receiver's 8080 is reachable, and 4317 on the same CIDR is not."""
        calls = self._capture(monkeypatch)
        setup_routing_control(
            FakeCfg(
                protocol="both",
                allowed_destinations="198.19.0.0/16:8080/tcp, 10.20.0.0/24",
            )
        )
        rules = [c for c in calls if c.startswith("iptables -A CULVERT_FWD -i")]
        assert rules[-6:] == [
            "iptables -A CULVERT_FWD -i tun+ -d 198.19.0.0/16 -p tcp --dport 8080"
            " -j ACCEPT",
            "iptables -A CULVERT_FWD -i wg0 -d 198.19.0.0/16 -p tcp --dport 8080"
            " -j ACCEPT",
            "iptables -A CULVERT_FWD -i tun+ -d 10.20.0.0/24 -j ACCEPT",
            "iptables -A CULVERT_FWD -i wg0 -d 10.20.0.0/24 -j ACCEPT",
            "iptables -A CULVERT_FWD -i tun+ -j DROP",
            "iptables -A CULVERT_FWD -i wg0 -j DROP",
        ]
        assert not any("4317" in c for c in calls)

    def test_every_rule_is_an_argv_list(self, monkeypatch):
        """No rule is a string a shell would split, whatever the config holds."""
        seen = []
        monkeypatch.setattr(network, "run", lambda cmd, **kw: seen.append(cmd))
        setup_routing_control(
            FakeCfg(
                protocol="both",
                allowed_destinations="198.19.0.0/16:8080/tcp",
                downstream_admin_cidrs="10.10.0.0/16",
            )
        )
        network.setup_forward_guards(FakeCfg(protocol="both"))
        assert seen
        assert all(isinstance(cmd, list) and cmd[0] == "iptables" for cmd in seen)

    def test_forward_jump_removed_before_chain_is_flushed(self, monkeypatch):
        """Detach FORWARD first, so a failed rebuild cannot leave traffic free.

        A flushed chain that is still jumped from a previous run matches nothing
        and falls through to the FORWARD policy, which is permissive.
        """
        calls = self._capture(monkeypatch)
        setup_routing_control(FakeCfg())
        detach = calls.index("iptables -D FORWARD -j CULVERT_FWD")
        flush = calls.index("iptables -F CULVERT_FWD")
        assert detach < flush, (
            "the chain is flushed while FORWARD still jumps at it, so traffic is"
            f" unfiltered for the length of the rebuild: {calls}"
        )


class TestRoutingControlFailsClosed:
    """A rule that does not install must abort, not be reported as applied.

    Routing control is what enforces client isolation, the egress allow-list and
    the downstream-admin gate. Logging success over a half-built chain hands the
    operator a server they believe is filtering and which is not.
    """

    def _failing_on(self, monkeypatch, fragment):
        """Make run() fail for any rule containing fragment, capturing the rest.

        Honours check= the way the real run() does, so a call the code passes
        check=False for stays tolerant here too.
        """
        calls = []

        def fake_run(cmd, **kw):
            line = " ".join(cmd)
            calls.append(line)
            if fragment in line and kw.get("check", True):
                raise subprocess.CalledProcessError(1, cmd)

        monkeypatch.setattr(network, "run", fake_run)
        return calls

    def test_failed_isolation_rule_aborts(self, monkeypatch):
        self._failing_on(monkeypatch, "-i tun+ -o tun+")
        with pytest.raises(network.FirewallError, match="client isolation"):
            setup_routing_control(FakeCfg())

    def test_failed_rule_never_installs_the_forward_jump(self, monkeypatch):
        calls = self._failing_on(monkeypatch, "-i tun+ -o tun+")
        with pytest.raises(network.FirewallError):
            setup_routing_control(FakeCfg())
        assert "iptables -I FORWARD 1 -j CULVERT_FWD" not in calls, (
            "the chain was pointed at from FORWARD despite a rule failing"
        )

    def test_failed_egress_allowlist_aborts(self, monkeypatch):
        self._failing_on(monkeypatch, "-d 10.20.0.0/24")
        with pytest.raises(network.FirewallError, match="egress"):
            setup_routing_control(FakeCfg(allowed_destinations="10.20.0.0/24"))

    def test_tolerant_calls_are_still_tolerant(self, monkeypatch):
        """-N and -D fail routinely (chain exists, rule absent) and must not abort."""
        self._failing_on(monkeypatch, "-N CULVERT_FWD")
        setup_routing_control(FakeCfg())


class TestLinkLocalGuard:
    """Clients must not reach 169.254.0.0/16 through the server.

    On any cloud instance that range carries the metadata service, so a client
    that routes it down the tunnel gets the HOST's credentials back - a VPN
    account escalated to cloud credentials. Link-local is not routable past the
    link, so nothing legitimate is denied.
    """

    def _capture(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            network, "run", lambda cmd, **kw: calls.append(" ".join(cmd))
        )
        return calls

    def test_link_local_is_dropped_for_each_tunnel_interface(self, monkeypatch):
        calls = self._capture(monkeypatch)
        network.setup_forward_guards(FakeCfg(protocol="both"))
        for iface in ("tun+", "wg0"):
            assert (
                f"iptables -A CULVERT_GUARD -i {iface} -d 169.254.0.0/16 -j DROP"
                in calls
            ), f"no link-local DROP for {iface}: {calls}"

    def test_guard_is_installed_even_without_routing_control(self, monkeypatch):
        """It is a default, not part of the opt-in feature.

        routing_control_enabled defaults to false, so a guard that only ran with
        it would leave the metadata service reachable on the configuration
        almost everyone runs.
        """
        calls = self._capture(monkeypatch)
        network.setup_forward_guards(
            FakeCfg(protocol="openvpn", routing_control_enabled=False)
        )
        assert "iptables -I FORWARD 1 -j CULVERT_GUARD" in calls

    def test_guard_jump_is_inserted_at_the_top_of_forward(self, monkeypatch):
        """Position 1, so it is evaluated before routing control's own chain."""
        calls = self._capture(monkeypatch)
        network.setup_forward_guards(FakeCfg())
        assert "iptables -I FORWARD 1 -j CULVERT_GUARD" in calls

    def test_existing_jump_is_removed_before_the_chain_is_rebuilt(self, monkeypatch):
        """Restarts must not stack duplicate jumps."""
        calls = self._capture(monkeypatch)
        network.setup_forward_guards(FakeCfg())
        detach = calls.index("iptables -D FORWARD -j CULVERT_GUARD")
        flush = calls.index("iptables -F CULVERT_GUARD")
        assert detach < flush

    def test_can_be_switched_off(self, monkeypatch):
        """An operator who needs link-local forwarded can turn it off."""
        calls = self._capture(monkeypatch)
        cfg = FakeCfg()
        cfg.block_link_local = False
        network.setup_forward_guards(cfg)
        assert calls == []

    def test_only_forward_is_touched(self, monkeypatch):
        """The server's own metadata access must survive.

        External PKI on AWS authenticates with the instance credentials the
        metadata service hands out, so filtering OUTPUT would break it.
        """
        calls = self._capture(monkeypatch)
        network.setup_forward_guards(FakeCfg(protocol="both"))
        assert not any("OUTPUT" in c or "INPUT" in c for c in calls), (
            f"the guard touched a chain other than FORWARD: {calls}"
        )
