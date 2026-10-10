"""The console summary leads with the score and groups findings by category (issue #53)."""

from __future__ import annotations

import re

from rich.console import Console

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.cli._summary import render
from pcap_doctor.models import CaptureInfo, Finding, Report, Stats


def _finding(code: str, severity: str = "medium", title: str = "t", scope: str = "s") -> Finding:
    return Finding.make(
        detector="d0.test", code=code, title=title, severity=severity, confidence="high",  # type: ignore[arg-type]
        category="test", summary="", scope=scope,
    )


def _report(findings: list[Finding]) -> Report:
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=10, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=findings)


def _text(report: Report, verbose: bool = False) -> str:
    console = Console(record=True, width=200, color_system=None)
    render(console, report, verbose=verbose)
    return console.export_text()


def test_score_line_comes_first_after_the_capture_line() -> None:
    lines = _text(_report([_finding("TLS_VERSION_DEPRECATED", "critical")])).splitlines()
    assert lines[1] == "Score 80/100 · needs work"


def test_categories_follow_the_catalog_order_with_count_and_worst() -> None:
    text = _text(_report([_finding("DNS_CLEARTEXT", "low"), _finding("TLS_VERSION_DEPRECATED", "high")]))
    assert text.index("Crypto  1 finding(s) · worst high") < text.index("DNS  1 finding(s) · worst low")


def test_top_three_per_category_unless_verbose() -> None:
    report = _report([_finding("DNS_CLEARTEXT", title=f"query {i}", scope=str(i)) for i in range(5)])
    assert _text(report).count("DNS_CLEARTEXT") == 3
    assert "+2 more (--verbose shows all)" in _text(report)
    assert _text(report, verbose=True).count("DNS_CLEARTEXT") == 5


def test_capture_text_cannot_inject_markup() -> None:
    text = _text(_report([_finding("DNS_CLEARTEXT", title="evil [/bold][red]x.example")]))
    assert "evil [/bold][red]x.example" in text


def test_no_findings_scores_100() -> None:
    assert "Score 100/100 · good" in _text(_report([]))
    assert "no findings" in _text(_report([]))


@requires_tshark
def test_score_flag_prints_only_the_integer(cli_runner, tmp_path, cache_dir) -> None:
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "-o", str(tmp_path), "--score"])
    assert result.exit_code == 0
    assert re.fullmatch(r"\d+\n", result.output)
