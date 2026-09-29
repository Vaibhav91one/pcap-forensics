"""`why` explains one finding by id prefix or frame, and refuses ambiguous input (issue #60)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcapforensics.cli import app
from pcapforensics.models import CaptureInfo, Evidence, Finding, Report, Stats
from pcapforensics.prompts import FENCE_LABEL


def _finding(code: str, frame: int, scope: str) -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=f"{code} title", severity="high", confidence="high",
        category="crypto", summary=f"{code} summary", scope=scope,
        evidence=[Evidence(frame=frame, field="tls.handshake.version", value="TLS 1.0")],
        remediation="Raise the minimum to TLS 1.2.",
    )


@pytest.fixture
def report_file(tmp_path: Path) -> Path:
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    findings = [
        _finding("TLS_VERSION_DEPRECATED", 4, "a"),
        _finding("TLS_CIPHER_WEAK", 4, "b"),
        _finding("TLS_NO_FORWARD_SECRECY", 9, "c"),
    ]
    report = Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=findings)
    path = tmp_path / "x.pf-report" / "report.json"
    path.parent.mkdir()
    path.write_text(report.model_dump_json())
    return path


def _run(cli_runner, *args: str):
    return cli_runner.invoke(app, ["why", *args], env={"COLUMNS": "200"})


def test_lookup_by_frame(cli_runner, report_file) -> None:
    result = _run(cli_runner, "9", "--report", str(report_file))
    assert result.exit_code == 0, result.output
    assert "TLS_NO_FORWARD_SECRECY" in result.output
    assert "frame 9" in result.output
    assert "How to fix" in result.output


def test_lookup_by_id_prefix_and_hash_prefix(cli_runner, report_file) -> None:
    report = Report.model_validate_json(report_file.read_text())
    target = report.findings[1]
    assert "TLS_CIPHER_WEAK" in _run(cli_runner, target.id[:-6], "--report", str(report_file)).output
    assert _run(cli_runner, target.id.rsplit(".", 1)[-1][:8], "--report", str(report_file)).exit_code == 0


def test_ambiguous_frame_lists_matches_and_exits_2(cli_runner, report_file) -> None:
    result = _run(cli_runner, "4", "--report", str(report_file))
    assert result.exit_code == 2
    assert "2 finding(s) match" in result.output


def test_no_match_exits_2(cli_runner, report_file) -> None:
    assert _run(cli_runner, "77", "--report", str(report_file)).exit_code == 2


def test_prompt_flag_prints_the_fix_prompt(cli_runner, report_file) -> None:
    result = _run(cli_runner, "9", "--report", str(report_file), "--prompt")
    assert result.exit_code == 0
    assert FENCE_LABEL in result.output


def test_report_is_found_in_the_current_directory(cli_runner, report_file, monkeypatch) -> None:
    monkeypatch.chdir(report_file.parent.parent)
    assert _run(cli_runner, "9").exit_code == 0
    monkeypatch.chdir(report_file.parent)
    assert _run(cli_runner, "9").exit_code == 2
