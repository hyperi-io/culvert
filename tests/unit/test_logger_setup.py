#  Project:      culvert
#  File:         test_logger_setup.py
#  Purpose:      Every process entry point installs scalo's logger before it logs
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Every process entry point installs scalo's logger before anything logs.

Without the call, loguru's bare default handler takes every line: no scalo
format and no secret scrubbing. scalo's ``setup`` is replaced with a recorder,
and each command is stopped at its first step after it, so no sink is installed.
"""

import importlib
import importlib.util
from pathlib import Path

import lib.config
import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


class _StoppedAtConfigError(Exception):
    """Raised in place of the config load, so a command ends straight after setup."""


def _stop(*_args, **_kwargs):
    raise _StoppedAtConfigError


def _load(filename: str):
    """Load a script whose filename is not a valid module name."""
    module_name = filename.removesuffix(".py").replace("-", "_") + "_logger_script"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None, f"cannot load {filename}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def events(monkeypatch) -> list[str]:
    """Record each scalo logger ``setup`` call, and refuse span export."""
    seen: list[str] = []

    def _setup(**kwargs) -> None:
        assert kwargs.get("otel_tracing") is False, "culvert starts no span exporter"
        seen.append("setup")

    monkeypatch.setattr("scalo.logger.setup", _setup)
    return seen


class TestEntrypoint:
    def test_a_command_sets_up_the_logger_once_before_loading_config(
        self, events, monkeypatch, clean_env
    ):
        entrypoint = importlib.import_module("entrypoint")
        monkeypatch.setattr(entrypoint.Config, "from_settings", classmethod(_stop))
        monkeypatch.setattr("sys.argv", ["entrypoint", "server"])

        with pytest.raises(_StoppedAtConfigError):
            entrypoint.main()

        assert events == ["setup"]

    def test_the_healthcheck_probe_skips_it(self, events, monkeypatch, clean_env):
        """The probe runs every few seconds and logs nothing."""
        entrypoint = importlib.import_module("entrypoint")
        # Port 1 on localhost: nothing listens, so the probe fails fast.
        monkeypatch.setenv("CULVERT_METRICS_ADDR", "127.0.0.1:1")
        monkeypatch.setattr("sys.argv", ["entrypoint", "healthcheck"])

        with pytest.raises(SystemExit):
            entrypoint.main()

        assert events == []

    def test_a_logger_that_cannot_start_stops_the_command(self, monkeypatch, clean_env):
        entrypoint = importlib.import_module("entrypoint")

        def _broken(**_kwargs) -> None:
            raise OSError("sink unavailable")

        monkeypatch.setattr("scalo.logger.setup", _broken)
        monkeypatch.setattr(entrypoint.Config, "from_settings", classmethod(_stop))
        monkeypatch.setattr("sys.argv", ["entrypoint", "server"])

        with pytest.raises(OSError, match="sink unavailable"):
            entrypoint.main()


class TestStandaloneScripts:
    @pytest.mark.parametrize(
        ("filename", "argv"),
        [
            ("generate-client.py", ["generate-client"]),
            ("revoke-client.py", ["revoke-client", "--list"]),
        ],
    )
    def test_sets_up_the_logger_once_before_loading_config(
        self, events, monkeypatch, clean_env, filename, argv
    ):
        script = _load(filename)
        monkeypatch.setattr(lib.config.Config, "from_settings", classmethod(_stop))
        monkeypatch.setattr("sys.argv", argv)

        with pytest.raises(_StoppedAtConfigError):
            script.main()

        assert events == ["setup"]

    def test_update_crl_sets_up_the_logger_before_its_first_line(
        self, events, monkeypatch, tmp_path
    ):
        script = _load("update-crl.py")
        monkeypatch.setattr(script, "PKI_DIR", tmp_path / "missing")
        monkeypatch.setattr(
            script.logger, "error", lambda *_a, **_k: events.append("error")
        )

        with pytest.raises(SystemExit):
            script.main()

        assert events == ["setup", "error"]
