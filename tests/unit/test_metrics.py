#  Project:      culvert
#  File:         test_metrics.py
#  Purpose:      Tests for metrics module parsing functions
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import contextlib
import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from lib.metrics import (
    _byte_delta,
    _reset_byte_tracking,
    collect_openvpn_status,
    parse_openvpn_status_v3,
    parse_wg_handshakes,
    parse_wg_transfer,
)

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"

# The identity an image build bakes in, as the info gauge should carry it.
BUILD_VERSION = "2.1.20"
BUILD_COMMIT = "abc1234"

# The families the collector stopped receiving when it stopped scraping culvert.
RUNTIME_FAMILIES = {
    "process_cpu_seconds_total",
    "process_max_fds",
    "process_open_fds",
    "process_resident_memory_bytes",
    "process_start_time_seconds",
    "process_virtual_memory_bytes",
    "python_gc_collections_total",
    "python_gc_objects_collected_total",
    "python_gc_objects_uncollectable_total",
    "python_info",
}

RUNTIME_COUNTERS = {name for name in RUNTIME_FAMILIES if name.endswith("_total")}

# The names and label keys consumers query; changing either breaks them.
VPN_FAMILIES = {
    "vpn_bytes_received_total": set(),
    "vpn_bytes_sent_total": set(),
    "vpn_connected_clients": {"listener", "protocol"},
    "vpn_connected_clients_total": set(),
    "vpn_connection_utilisation": set(),
    "vpn_crl_seconds_until_expiry": set(),
    "vpn_max_clients": set(),
    "vpn_openvpn_up": set(),
    "vpn_wireguard_up": set(),
}

# scalo's AppMetrics group registers beside the vpn_* families. `info` is the
# identity gauge a liveness check keys on. An OTLP push carries only the
# instruments that hold a value, so of the group these two reach a collector.
APP_FAMILIES = {
    "info": {"app", "commit", "version"},
    "start_time_seconds": set(),
}

# Every family the OTel-mode /metrics endpoint serves, by its TYPE-line name.
OTEL_SCRAPE_FAMILIES = (
    RUNTIME_FAMILIES | set(VPN_FAMILIES) | set(APP_FAMILIES) | {"target_info"}
)


@contextlib.contextmanager
def _otlp_sink():
    """Accept every OTLP/HTTP push on an ephemeral 127.0.0.1 port.

    A provider's shutdown flushes what it holds, and a push to a closed port
    retries until the shutdown deadline, so a test that shuts a provider down
    needs somewhere for the flush to land.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args) -> None:
            pass  # silence request logging during tests

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _metrics_by_name(metrics_data) -> dict:
    """Index an OTel MetricsData by metric name."""
    found = {}
    for resource_metrics in metrics_data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                found[metric.name] = metric
    return found


def _scrape_runtime_samples() -> dict[str, list]:
    """Parse the runtime families out of the default registry's exposition text."""
    from prometheus_client import REGISTRY, generate_latest
    from prometheus_client.parser import text_string_to_metric_families

    samples: dict[str, list] = {}
    text = generate_latest(REGISTRY).decode()
    for family in text_string_to_metric_families(text):
        if not family.name.startswith(("process_", "python_")):
            continue
        for sample in family.samples:
            samples.setdefault(sample.name, []).append(sample)
    return samples


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


class TestByteDelta:
    """Snapshot byte totals -> monotonic counter increments."""

    def setup_method(self):
        _reset_byte_tracking()

    def test_first_poll_baselines_without_increment(self):
        """First reading establishes a baseline and adds nothing."""
        assert _byte_delta("rx", 5000) == 0

    def test_increase_returns_positive_delta(self):
        """A growing snapshot reports the difference since last poll."""
        _byte_delta("rx", 1000)
        assert _byte_delta("rx", 1500) == 500

    def test_unchanged_returns_zero(self):
        """A flat snapshot adds nothing."""
        _byte_delta("tx", 800)
        assert _byte_delta("tx", 800) == 0

    def test_decrease_rebaselines_without_negative_increment(self):
        """A drop (client disconnect / interface restart) never goes negative."""
        _byte_delta("rx", 9000)
        assert _byte_delta("rx", 200) == 0
        # Subsequent growth is measured from the new, lower baseline.
        assert _byte_delta("rx", 700) == 500

    def test_rx_and_tx_tracked_independently(self):
        """The two directions keep separate baselines."""
        _byte_delta("rx", 100)
        _byte_delta("tx", 100)
        assert _byte_delta("rx", 350) == 250
        assert _byte_delta("tx", 180) == 80


class TestCrlExpiryGauge:
    """The CRL expiry has to reach the scrape, not just the log.

    An expired CRL makes OpenVPN refuse every client, so it needs to be
    alertable. Logs are what got missed last time.
    """

    def test_expiry_is_exported_with_the_real_margin(self, tmp_path, write_crl):
        """A real CRL reaches a real scrape carrying its actual margin.

        Asserts the value, not just the name: a registered-but-never-set
        gauge exports as 0, which would read as "expires now" and pass a
        name-only check.
        """
        from datetime import UTC, datetime, timedelta

        from lib import metrics as m

        write_crl(tmp_path / "crl.pem", datetime.now(UTC) + timedelta(days=60))

        adapter = m.init_metrics(
            max_clients=10,
            protocol="openvpn",
            pki_dir=str(tmp_path),
        )
        scrape = adapter.get_metrics().decode()

        value = None
        for line in scrape.splitlines():
            if line.startswith("vpn_crl_seconds_until_expiry "):
                value = float(line.split()[1])
        assert value is not None, "gauge missing from the scrape"
        assert 59.9 < value / 86400 < 60.1

    def test_absent_pki_dir_does_not_break_the_scrape(self):
        """No pki_dir configured must not raise on update."""
        from lib import metrics as m

        m._pki_dir = ""
        m.update_metrics()


class TestParsersSkipMalformedInput:
    """A garbled line costs that line, never the whole scrape."""

    def test_openvpn_client_with_non_numeric_bytes_is_still_counted(self):
        line = "CLIENT_LIST\tuser1\t1.2.3.4:1194\t10.0.0.2\t\tlots\t200\t2026-04-01"
        status = parse_openvpn_status_v3(line)
        assert status.client_count == 1
        assert status.clients == []
        assert status.bytes_received == 0

    def test_wg_transfer_skips_short_and_non_numeric_lines(self):
        output = "short\tline\nkey1=\tmany\t1\nkey2=\t10\t20\n"
        peers = parse_wg_transfer(output)
        assert set(peers) == {"key2="}
        assert (peers["key2="].rx, peers["key2="].tx) == (10, 20)

    def test_wg_handshakes_skip_short_and_non_numeric_lines(self):
        output = "lonely\nkey1=\tyesterday\nkey2=\t1700000000\n"
        peers = parse_wg_handshakes(output)
        assert set(peers) == {"key2="}
        assert peers["key2="].timestamp == 1700000000

    def test_unreadable_status_file_reads_as_absent(self, tmp_path):
        """A path that exists but cannot be read must not raise into the scrape."""
        assert collect_openvpn_status(str(tmp_path), "udp") is None


class TestScrapeAdapter:
    """The observability port renders whatever the manager holds."""

    def test_wireguard_mode_scrapes_without_a_running_interface(self, tmp_path):
        """No wg0 (or no wg at all) reads as zero peers, not a failed scrape."""
        from lib import metrics as m

        adapter = m.init_metrics(max_clients=10, protocol="both", pki_dir="")
        scrape = adapter.get_metrics().decode()

        assert 'vpn_connected_clients{listener="wg0",protocol="wireguard"} 0.0' in (
            scrape
        )
        assert "vpn_wireguard_up 0.0" in scrape
        assert "text/plain" in adapter.get_content_type()

    def test_scrape_before_init_is_refused(self, monkeypatch):
        from lib import metrics as m

        monkeypatch.setattr(m, "_mgr", None)
        with pytest.raises(RuntimeError, match="before init_metrics"):
            m.ScrapeAdapter().get_metrics()

    def test_a_backend_error_on_one_gauge_does_not_raise(self):
        """Setting a labelled gauge without its labels fails inside the backend."""
        from lib import metrics as m

        m.init_metrics(max_clients=10, protocol="openvpn", pki_dir="")
        m._gauge_set(m._g_connected, 1)
        m._gauge_set(None, 1)


class TestBuildIdentity:
    """The version and commit the image build baked in label the info gauge."""

    def test_reads_the_files_the_image_build_wrote(self, tmp_path):
        from lib import metrics as m

        (tmp_path / "VERSION").write_text(f"{BUILD_VERSION}\n", encoding="utf-8")
        (tmp_path / "COMMIT").write_text(f"{BUILD_COMMIT}\n", encoding="utf-8")

        assert m._build_identity(tmp_path) == (BUILD_VERSION, BUILD_COMMIT)

    def test_a_build_outside_the_image_reads_as_dev_and_unknown(self, tmp_path):
        from lib import metrics as m

        assert m._build_identity(tmp_path) == ("dev", "unknown")

    def test_an_empty_commit_reads_as_unknown(self, tmp_path):
        """The Dockerfile's COMMIT build arg defaults to empty, and CI passes none."""
        from lib import metrics as m

        (tmp_path / "VERSION").write_text(f"{BUILD_VERSION}\n", encoding="utf-8")
        (tmp_path / "COMMIT").write_text("\n", encoding="utf-8")

        assert m._build_identity(tmp_path) == (BUILD_VERSION, "unknown")

    def test_an_unreadable_file_reads_as_its_fallback(self, tmp_path):
        """A directory standing where the file belongs cannot be read as text."""
        from lib import metrics as m

        (tmp_path / "VERSION").mkdir()

        assert m._build_identity(tmp_path)[0] == "dev"


class TestInfoGauge:
    """scalo's identity gauge, which a liveness check keys on by name."""

    def test_the_scrape_carries_the_build_identity(self, tmp_path, monkeypatch):
        from lib import metrics as m
        from prometheus_client.parser import text_string_to_metric_families

        (tmp_path / "VERSION").write_text(f"{BUILD_VERSION}\n", encoding="utf-8")
        (tmp_path / "COMMIT").write_text(f"{BUILD_COMMIT}\n", encoding="utf-8")
        monkeypatch.setattr(m, "BUILD_INFO_DIR", tmp_path)

        adapter = m.init_metrics(max_clients=10, protocol="openvpn", pki_dir="")
        scrape = adapter.get_metrics().decode()

        samples = []
        for family in text_string_to_metric_families(scrape):
            samples.extend(s for s in family.samples if s.name == "info")
        assert [(s.labels, s.value) for s in samples] == [
            (
                {"app": "culvert", "commit": BUILD_COMMIT, "version": BUILD_VERSION},
                1.0,
            )
        ]


class TestRuntimeMetricsOverOtlp:
    """The scrape's process and runtime families reach an OTLP reader.

    The collector no longer scrapes culvert pods, so the push is the only path
    these families have off the pod.
    """

    @pytest.fixture
    def pushed(self):
        """Collect the runtime instruments once through an in-memory reader."""
        from lib import metrics as m
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader

        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader], shutdown_on_exit=False)
        m.register_runtime_metrics(provider.get_meter("culvert"))
        data = reader.get_metrics_data()
        provider.shutdown()
        return _metrics_by_name(data)

    def test_every_lost_family_is_pushed(self, pushed):
        assert RUNTIME_FAMILIES <= set(pushed)

    def test_pushed_names_are_the_names_the_scrape_serves(self, pushed):
        assert set(pushed) == set(_scrape_runtime_samples())

    def test_counters_push_as_monotonic_sums_and_the_rest_as_gauges(self, pushed):
        """The collector files a monotonic sum and a gauge in different tables."""
        from opentelemetry.sdk.metrics.export import Gauge, Sum

        for name, metric in pushed.items():
            if name in RUNTIME_COUNTERS:
                assert isinstance(metric.data, Sum), name
                assert metric.data.is_monotonic, name
            else:
                assert isinstance(metric.data, Gauge), name

    def test_labels_match_the_scrape(self, pushed):
        scraped = _scrape_runtime_samples()
        for name in ("python_info", "python_gc_collections_total"):
            pushed_labels = [
                dict(point.attributes or {}) for point in pushed[name].data.data_points
            ]
            scraped_labels = [sample.labels for sample in scraped[name]]
            assert sorted(pushed_labels, key=str) == sorted(scraped_labels, key=str)

    def test_values_are_read_from_the_same_collectors_as_the_scrape(self, pushed):
        scraped = _scrape_runtime_samples()
        for name in ("python_info", "process_max_fds"):
            pushed_value = pushed[name].data.data_points[0].value
            assert pushed_value == scraped[name][0].value, name

    def test_the_scrape_is_unchanged_by_the_push(self):
        """Registering the push adds nothing to the /metrics registry."""
        from lib import metrics as m
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        from prometheus_client import REGISTRY, generate_latest

        def headers() -> list[str]:
            text = generate_latest(REGISTRY).decode()
            return [line for line in text.splitlines() if line.startswith("#")]

        before = headers()
        reader = InMemoryMetricReader()
        provider = MeterProvider(metric_readers=[reader], shutdown_on_exit=False)
        m.register_runtime_metrics(provider.get_meter("culvert"))
        reader.get_metrics_data()
        provider.shutdown()
        assert headers() == before


# A child process, because the OTel API allows one global MeterProvider per
# process; the hour-long interval and os._exit mean no exporter is ever dialled.
OTEL_MODE_PROBE = """
import json
import os
from pathlib import Path

from opentelemetry import metrics as otel_metrics
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from lib import metrics as m


def collect(reader):
    out = {"metrics": {}, "types": {}, "points": {}, "resource": {}, "scopes": []}
    for rm in reader.get_metrics_data().resource_metrics:
        out["resource"] = dict(rm.resource.attributes)
        for sm in rm.scope_metrics:
            out["scopes"].append(sm.scope.name)
            for metric in sm.metrics:
                keys = set()
                points = []
                for point in metric.data.data_points:
                    attributes = dict(point.attributes or {})
                    keys.update(attributes)
                    points.append({"attributes": attributes, "value": point.value})
                out["metrics"][metric.name] = sorted(keys)
                out["types"][metric.name] = type(metric.data).__name__
                out["points"][metric.name] = points
    return out


m.BUILD_INFO_DIR = Path(os.environ["PROBE_BUILD_INFO_DIR"])
adapter = m.init_metrics(
    max_clients=10,
    protocol="both",
    otel_enabled=True,
    otel_endpoint="http://127.0.0.1:9",
)
vpn_reader = InMemoryMetricReader()
otel_metrics.get_meter_provider().add_metric_reader(vpn_reader)
m.update_metrics()
m._c_bytes_rx.inc(1)
m._c_bytes_tx.inc(1)
m._gauge_set(m._g_crl_expiry, 1)

result = {"vpn": collect(vpn_reader), "runtime": None}
runtime_provider = getattr(m, "_runtime_provider", None)
if runtime_provider is not None:
    runtime_reader = InMemoryMetricReader()
    runtime_provider.add_metric_reader(runtime_reader)
    result["runtime"] = collect(runtime_reader)

scrape = adapter.get_metrics().decode()
result["scrape"] = sorted(
    line.split()[2] for line in scrape.splitlines() if line.startswith("# TYPE ")
)
print(json.dumps(result), flush=True)
os._exit(0)
"""


@pytest.fixture(scope="module")
def otel_mode(tmp_path_factory):
    """Run OTel-mode init once and return what each reader and the scrape saw."""
    workdir = tmp_path_factory.mktemp("otel-mode")
    # What the image build bakes under /etc/vpn, in a directory the child can read.
    build_info = workdir / "build-info"
    build_info.mkdir()
    (build_info / "VERSION").write_text(f"{BUILD_VERSION}\n", encoding="utf-8")
    (build_info / "COMMIT").write_text(f"{BUILD_COMMIT}\n", encoding="utf-8")
    # A built environment, so nothing from the caller's reaches the child or a report.
    env = {
        "HOME": str(workdir),
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
        "OTEL_METRIC_EXPORT_INTERVAL": "3600000",
        "OTEL_SERVICE_NAME": "culvert-under-test",
        "PATH": "/usr/bin:/bin",
        "PROBE_BUILD_INFO_DIR": str(build_info),
        "PYTHONPATH": str(SCRIPTS_DIR),
    }
    result = subprocess.run(
        [sys.executable, "-c", OTEL_MODE_PROBE],
        capture_output=True,
        check=False,
        cwd=workdir,
        encoding="utf-8",
        env=env,
        errors="replace",
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


class TestOtelModeContract:
    """What a running culvert pushes and serves in OTel mode."""

    def test_vpn_names_and_label_keys_are_unchanged_over_otlp(self, otel_mode):
        pushed = {
            name: set(keys)
            for name, keys in otel_mode["vpn"]["metrics"].items()
            if name.startswith("vpn_")
        }
        assert pushed == VPN_FAMILIES

    def test_the_app_identity_families_are_pushed_beside_the_vpn_ones(self, otel_mode):
        pushed = {
            name: set(keys)
            for name, keys in otel_mode["vpn"]["metrics"].items()
            if not name.startswith("vpn_")
        }
        assert pushed == APP_FAMILIES

    def test_info_is_a_gauge_carrying_the_build_identity(self, otel_mode):
        """A collector files a gauge apart from a sum, and a liveness check reads gauges.

        The reader's resource names the service the collector files `info` under.
        """
        vpn = otel_mode["vpn"]
        assert vpn["types"]["info"] == "Gauge"
        assert vpn["points"]["info"] == [
            {
                "attributes": {
                    "app": "culvert",
                    "commit": BUILD_COMMIT,
                    "version": BUILD_VERSION,
                },
                "value": 1.0,
            }
        ]
        assert vpn["resource"]["service.name"] == "culvert-under-test"

    def test_scrape_serves_exactly_the_expected_families(self, otel_mode):
        assert set(otel_mode["scrape"]) == OTEL_SCRAPE_FAMILIES

    def test_runtime_families_are_pushed(self, otel_mode):
        assert otel_mode["runtime"] is not None, "no runtime push was started"
        assert RUNTIME_FAMILIES <= set(otel_mode["runtime"]["metrics"])

    def test_runtime_push_is_the_same_source_as_the_vpn_push(self, otel_mode):
        """Same resource and scope, so the collector files both under one pod."""
        assert otel_mode["runtime"] is not None, "no runtime push was started"
        assert otel_mode["runtime"]["resource"] == otel_mode["vpn"]["resource"]
        assert otel_mode["runtime"]["scopes"] == ["culvert"]
        assert set(otel_mode["vpn"]["scopes"]) == {"culvert"}

    def test_service_name_comes_from_the_otel_env(self, otel_mode):
        assert otel_mode["vpn"]["resource"]["service.name"] == "culvert-under-test"


class TestOtelEndpointSetting:
    """culvert's own endpoint setting reaches both OTLP pushes without the SDK's variable."""

    def test_the_culvert_endpoint_alone_is_where_both_pushes_go(self, monkeypatch):
        from lib import metrics as m

        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
        sections = []
        monkeypatch.setattr(
            m, "_start_runtime_push", lambda _app, section: sections.append(section)
        )

        with _otlp_sink() as endpoint:
            m._init_metrics(
                "culvert",
                otel_enabled=True,
                otel_endpoint=endpoint,
                otel_protocol="http",
                otel_insecure=False,
            )
            try:
                assert m._mgr.backend_name == "opentelemetry"
                assert m._mgr._backend.resolved.endpoint == endpoint
                assert m._mgr._backend.resolved.protocol == "http"
                assert sections == [{"endpoint": endpoint, "protocol": "http"}]
            finally:
                m._mgr._backend._provider.shutdown(timeout_millis=1000)
