"""`--profile ota` / `profile = "ota"`: a preset config fragment; config keys and CLI flags override it (issue #58)."""

from __future__ import annotations

import json
import re

import pytest

from conftest import FIXTURES, requires_tshark
from pcapforensics.cli import app
from pcapforensics.config import ConfigError, load, parse

OTA = ("Crypto", "Credentials", "Cleartext", "DNS")


def test_profile_fills_keys_the_table_leaves_out() -> None:
    config = parse({"profile": "ota"}, "cfg")
    assert (config.profile, config.categories, config.fail_on) == ("ota", OTA, "high")
    assert parse({"profile": "ota", "fail_on": "critical"}, "cfg").fail_on == "critical"
    assert parse({"fail_on": "low"}, "cfg", profile="ota").fail_on == "low"


def test_profile_without_a_config_file(tmp_path) -> None:
    config = load(cwd=tmp_path, profile="ota")
    assert (config.categories, config.fail_on, config.source) == (OTA, "high", "profile ota")


@pytest.mark.parametrize(
    ("data", "profile", "message"),
    [
        ({}, "nope", "--profile: unknown profile nope; valid: ota"),
        ({"profile": "nope"}, None, "cfg: unknown profile nope; valid: ota"),
        ({"categories": ["Voip"]}, None, "unknown categories Voip"),
        ({"fail_on": "urgent"}, None, "fail_on urgent invalid"),
    ],
)
def test_bad_profile_category_or_fail_on_is_rejected(data: dict, profile: str | None, message: str) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        parse(data, "cfg", profile)


def test_unknown_profile_exits_2_before_tshark(cli_runner, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("analyze must not run")

    monkeypatch.setattr("pcapforensics.cli.analyze.analyze", boom)
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "sip_rtp.pcap"), "--profile", "nope"])
    assert result.exit_code == 2


def _codes(tmp_path, name: str) -> set[str]:
    return {f["code"] for f in json.loads((tmp_path / name / "report.json").read_text())["findings"]}


@requires_tshark
@pytest.mark.parametrize("pcap", ["sip_rtp.pcap", "syn_scan.pcap"])
def test_ota_drops_voice_and_network_findings(cli_runner, tmp_path, cache_dir, pcap) -> None:
    cli_runner.invoke(app, ["analyze", str(FIXTURES / pcap), "-o", str(tmp_path / "all"), "-q"])
    assert _codes(tmp_path, "all")  # the capture does have findings without the profile
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / pcap), "-o", str(tmp_path / "ota"), "-q", "--profile", "ota"])
    assert result.exit_code == 0
    assert _codes(tmp_path, "ota") == set()


@requires_tshark
def test_ota_fails_on_high_and_flags_win(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(FIXTURES / "weak_tls.pcap")
    assert cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "a"), "-q", "--profile", "ota"]).exit_code == 1
    flags = ["analyze", pcap, "-o", str(tmp_path / "b"), "-q", "--profile", "ota", "--fail-on", "none"]
    assert cli_runner.invoke(app, flags).exit_code == 0
    voice = ["analyze", str(FIXTURES / "sip_rtp.pcap"), "-o", str(tmp_path / "v"), "-q", "--profile", "ota", "--category", "Voice"]
    cli_runner.invoke(app, voice)
    assert _codes(tmp_path, "v")
