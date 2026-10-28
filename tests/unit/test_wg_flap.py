#  Project:      culvert
#  File:         test_wg_flap.py
#  Purpose:      Tests for WireGuard endpoint flap detection (shared keys)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import pytest
from lib.metrics import parse_wg_endpoints
from lib.wireguard import EndpointFlapDetector

A = "203.0.113.5:51820"
B = "198.51.100.9:40001"
C = "192.0.2.77:33000"


def run(steps, window=600.0, announce_every=600.0):
    """Feed (seconds, endpoint) steps for one peer, return each step's result."""
    detector = EndpointFlapDetector(window=window, announce_every=announce_every)
    return [detector.observe("peer", endpoint, t) for t, endpoint in steps]


class TestEndpointFlapDetector:
    @pytest.mark.parametrize(
        "steps",
        [
            pytest.param([(0, A), (15, A), (30, A)], id="steady"),
            pytest.param([(0, A), (15, B), (30, B), (45, B)], id="roam-and-stay"),
            pytest.param([(0, A), (15, B), (30, C)], id="roam-twice-new-addresses"),
            pytest.param([(0, A), (15, B), (900, A)], id="return-after-window"),
        ],
    )
    def test_a_roaming_client_never_flaps(self, steps):
        assert all(result is None for result in run(steps))

    def test_two_devices_taking_turns_flap_on_the_return(self):
        results = run([(0, A), (15, B), (30, A), (45, B)])
        assert results[0] is None
        assert results[1] is None
        assert results[2]["endpoints"] == sorted([A, B])
        assert results[3] is not None

    def test_a_steady_flap_is_announced_once_per_interval_but_always_counted(self):
        results = run(
            [(0, A), (15, B), (30, A), (45, B), (60, A), (200, B)], announce_every=100
        )
        flaps = [r for r in results if r is not None]
        assert [r["announce"] for r in flaps] == [True, False, False, True]

    def test_peers_are_tracked_separately(self):
        detector = EndpointFlapDetector()
        detector.observe("one", A, 0)
        detector.observe("two", B, 1)
        assert detector.observe("one", B, 2) is None
        assert detector.observe("two", A, 3) is None

    def test_a_peer_that_leaves_the_interface_is_forgotten(self):
        detector = EndpointFlapDetector()
        detector.observe("peer", A, 0)
        detector.observe("peer", B, 1)
        detector.forget_missing(set())
        assert detector.observe("peer", A, 2) is None


class TestParseWgEndpoints:
    def test_reads_pubkey_and_endpoint(self):
        out = f"keyA=\t{A}\nkeyB=\t[2001:db8::1]:51820\n"
        assert parse_wg_endpoints(out) == {
            "keyA=": A,
            "keyB=": "[2001:db8::1]:51820",
        }

    @pytest.mark.parametrize("out", ["", "\n", "keyA=\t(none)\n", "keyA=\n", "junk"])
    def test_skips_peers_without_an_endpoint_and_malformed_lines(self, out):
        assert parse_wg_endpoints(out) == {}
