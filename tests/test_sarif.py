"""`--sarif PATH` writes the shown findings as SARIF 2.1.0 for code-scanning upload (issue #56)."""

from __future__ import annotations

import json

from conftest import FIXTURES, requires_tshark
from pcapforensics.baseline import finding_fingerprint
from pcapforensics.cli import app
from pcapforensics.models import CaptureInfo, Evidence, Finding, Report, Stats
from pcapforensics.output import sarif


def _finding(code: str, severity: str, frames: tuple[int, ...] = ()) -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=f"{code} title", severity=severity, confidence="high",
        category="crypto", summary="why", scope=f"{code}{severity}",
        evidence=[Evidence(frame=n, field="f", value="v") for n in frames],
    )


def _report(findings: list[Finding]) -> Report:
    capture = CaptureInfo(
        path="/abs/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=findings)


def test_levels_rule_ids_and_fingerprints() -> None:
    findings = [
        _finding("TLS_CIPHER_WEAK", "critical", (4, 3, 4)),
        _finding("DNS_CLEARTEXT", "medium"),
        _finding("TLS_CERT_EXPIRING", "info"),
    ]
    run = sarif(_report(findings))["runs"][0]
    results = run["results"]
    assert [r["ruleId"] for r in results] == ["TLS_CIPHER_WEAK", "DNS_CLEARTEXT", "TLS_CERT_EXPIRING"]
    assert [r["level"] for r in results] == ["error", "warning", "note"]
    assert [r["partialFingerprints"]["doctorFinding/v1"] for r in results] == [finding_fingerprint(f) for f in findings]
    assert run["properties"]["score"] == {"value": 75, "label": "needs work", "model": "pcap/1", "coverage_gaps": 0}
    assert results[0]["properties"]["frames"] == [3, 4]
    assert results[0]["message"]["text"] == "TLS_CIPHER_WEAK title. why"
    rules = run["tool"]["driver"]["rules"]
    assert all(rules[r["ruleIndex"]]["id"] == r["ruleId"] for r in results)


def test_rule_is_listed_once_at_its_worst_severity() -> None:
    doc = sarif(_report([_finding("TLS_CIPHER_WEAK", "low"), _finding("TLS_CIPHER_WEAK", "high")]))
    (rule,) = doc["runs"][0]["tool"]["driver"]["rules"]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "8.0"
    assert rule["shortDescription"]["text"] == "Weak or prohibited cipher suite negotiated"


def test_document_header_and_artifact_uri() -> None:
    report = _report([_finding("DNS_CLEARTEXT", "medium")])
    doc = sarif(report)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "pcap-doctor"
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/abs/x.pcap"
    given = sarif(report, artifact_uri="captures/x.pcap")["runs"][0]["results"][0]
    assert given["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "captures/x.pcap"
    assert sarif(_report([]))["runs"][0]["results"] == []


@requires_tshark
def test_cli_writes_sarif_for_the_shown_findings(cli_runner, tmp_path, cache_dir) -> None:
    pcap = FIXTURES / "weak_tls.pcap"
    out = tmp_path / "scan.sarif"
    assert cli_runner.invoke(app, ["analyze", str(pcap), "-o", str(tmp_path / "a"), "-q", "--sarif", str(out)]).exit_code == 0
    doc = json.loads(out.read_text())
    report = json.loads((tmp_path / "a" / "report.json").read_text())
    assert len(doc["runs"][0]["results"]) == len(report["findings"]) > 0
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == pcap.as_posix()

    base = tmp_path / "a" / "report.json"
    again = tmp_path / "again.sarif"
    cli_runner.invoke(app, ["analyze", str(pcap), "-o", str(tmp_path / "b"), "-q", "--baseline", str(base), "--sarif", str(again)])
    assert json.loads(again.read_text())["runs"][0]["results"] == []
