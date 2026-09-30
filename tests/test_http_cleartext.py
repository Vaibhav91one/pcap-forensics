"""Plain HTTP is reported: high for a firmware-like download, medium otherwise; queries never leak (issue #91)."""

from __future__ import annotations

import pytest

from conftest import codes, fixture, requires_tshark
from pcapforensics.cli import app
from pcapforensics.detectors.transport_exposure import _looks_like_firmware, _path_only


@pytest.mark.parametrize(
    ("uri", "firmware"),
    [
        ("/firmware/v2.1.bin", True),
        ("/fw/latest", True),
        ("/device/update/manifest.json", True),
        ("/pkgs/agent_1.2_arm.ipk?sig=abc", True),
        ("/image.IMG", True),
        ("/index.html", False),
        ("/api/firmware-status", False),  # a word inside a segment is not a firmware path
        (None, False),
    ],
)
def test_firmware_paths(uri: str | None, firmware: bool) -> None:
    assert _looks_like_firmware(uri) is firmware


def test_query_strings_are_dropped() -> None:
    assert _path_only("/status.html?token=secret") == "/status.html?<query removed>"
    assert _path_only("/plain") == "/plain"
    assert _path_only(None) == ""


@requires_tshark
def test_plain_http_is_reported_per_flow(analyze_capture) -> None:
    result = analyze_capture(fixture("http_cleartext.pcap"))
    found = sorted((f for f in result.report.findings if f.code == "HTTP_CLEARTEXT"), key=lambda f: f.severity)
    assert [f.severity for f in found] == ["high", "medium"]
    firmware, page = found
    assert "CWE-494" in firmware.references and "firmware" in firmware.tags
    assert firmware.evidence[0].frame == 3
    assert firmware.evidence[0].value == "GET updates.example/firmware/v2.1.bin"
    assert page.evidence[0].value == "GET portal.example/status.html?<query removed>"


@requires_tshark
def test_the_query_token_never_reaches_a_report(analyze_capture) -> None:
    result = analyze_capture(fixture("http_cleartext.pcap"))
    joined = "".join(path.read_text() for path in result.artifacts)
    assert "pf-q-4a7b1c9d" not in joined


@requires_tshark
def test_http_with_credentials_is_also_plain_http_and_tls_stays_silent(analyze_capture) -> None:
    assert {"HTTP_CLEARTEXT_AUTH", "HTTP_CLEARTEXT"} <= codes(analyze_capture(fixture("http_basic.pcap")))
    assert "HTTP_CLEARTEXT" not in codes(analyze_capture(fixture("strong_tls13.pcap")))


@requires_tshark
def test_ota_profile_fails_a_plain_http_firmware_download(cli_runner, tmp_path, cache_dir) -> None:
    args = ["analyze", str(fixture("http_cleartext.pcap")), "-o", str(tmp_path / "r"), "-q", "--profile", "ota"]
    assert cli_runner.invoke(app, args).exit_code == 1
