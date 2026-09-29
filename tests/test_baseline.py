"""`--baseline` reports and gates only findings that are new since an earlier report (issue #55)."""

from __future__ import annotations

import json

from conftest import FIXTURES, requires_tshark
from pcapforensics.baseline import load_baseline, new_since, version_drift
from pcapforensics.cli import app
from pcapforensics.models import CaptureInfo, Finding, Report, Stats


def _finding(code: str) -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=code, severity="high", confidence="high",
        category="crypto", summary="", scope=code,
    )


def _report(codes: list[str], versions: dict[str, str] | None = None) -> Report:
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(
        generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[],
        findings=[_finding(c) for c in codes], detector_versions=versions or {},
    )


def test_new_since_matches_by_id() -> None:
    old, now = _report(["A", "B"]), _report(["B", "C"])
    assert [f.code for f in new_since(old, now.findings)] == ["C"]


def test_version_drift_names_changed_detectors() -> None:
    old = _report([], {"d1.tls_cipher": "1", "d2.x": "1"})
    assert version_drift(old, _report([], {"d1.tls_cipher": "2", "d2.x": "1", "d9.new": "1"})) == ["d1.tls_cipher"]


def test_load_baseline_accepts_report_and_envelope(tmp_path) -> None:
    report = _report(["A"])
    (tmp_path / "r.json").write_text(report.model_dump_json())
    (tmp_path / "e.json").write_text(json.dumps({"tool": "pcap-doctor", "report": report.model_dump(mode="json")}))
    assert load_baseline(tmp_path / "r.json").findings[0].id == report.findings[0].id
    assert load_baseline(tmp_path / "e.json").findings[0].id == report.findings[0].id


def test_bad_baseline_exits_2_before_tshark(cli_runner, tmp_path, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("analyze must not run")

    monkeypatch.setattr("pcapforensics.cli.analyze.analyze", boom)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "--baseline", str(bad)])
    assert result.exit_code == 2


@requires_tshark
def test_capture_against_its_own_report_has_nothing_new(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(FIXTURES / "weak_tls.pcap")
    assert cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "a"), "-q"]).exit_code == 0
    base = tmp_path / "a" / "report.json"
    result = cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "b"), "--baseline", str(base), "--fail-on", "low"])
    assert result.exit_code == 0
    assert "0 new finding(s) since the baseline" in result.output
    assert json.loads((tmp_path / "b" / "report.json").read_text())["findings"]  # artifacts stay complete


@requires_tshark
def test_removed_baseline_finding_is_exactly_the_new_one(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(FIXTURES / "weak_tls.pcap")
    cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "a"), "-q"])
    base = tmp_path / "a" / "report.json"
    data = json.loads(base.read_text())
    dropped = data["findings"].pop()
    base.write_text(json.dumps(data))
    result = cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "b"), "--baseline", str(base), "--json"])
    assert json.loads(result.output)["new_findings"] == [dropped["id"]]
