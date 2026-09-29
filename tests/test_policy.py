"""Filter options are validated before tshark runs and applied in one place (issue #52)."""

from __future__ import annotations

import pytest

from conftest import FIXTURES, requires_tshark
from pcapforensics.cli import app
from pcapforensics.models import Finding
from pcapforensics.policy import PolicyError, apply, validate


def _finding(code: str, severity: str = "high") -> Finding:
    return Finding.make(
        detector="d0.test", code=code, title=code, severity=severity, confidence="high",  # type: ignore[arg-type]
        category="test", summary="", scope=code,
    )


@pytest.mark.parametrize(
    "args",
    [
        ["--only", "nope"],
        ["--category", "Nope"],
        ["--min-severity", "severe"],
        ["--fail-on", "hgh"],
    ],
)
def test_unknown_option_value_exits_2_before_tshark(cli_runner, monkeypatch, args) -> None:
    def boom(*_a, **_k):
        raise AssertionError("analyze must not run")

    monkeypatch.setattr("pcapforensics.cli.analyze.analyze", boom)
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "weak_tls.pcap"), *args])
    assert result.exit_code == 2
    assert "valid:" in result.output


def test_valid_values_pass_validation() -> None:
    validate(only=["d4.dns_quic_ssh"], categories=["DNS", "SSH & QUIC"], min_severity="low", fail_on="none")


def test_pipeline_rejects_unknown_values_too(tmp_path) -> None:
    from pcapforensics.pipeline import analyze

    with pytest.raises(PolicyError):
        analyze(FIXTURES / "weak_tls.pcap", tmp_path, categories=("Nope",))


def test_category_keeps_only_that_category() -> None:
    findings = [_finding("DNS_EXTERNAL_RESOLVER"), _finding("TLS_VERSION_DEPRECATED"), _finding("NOT_A_RULE")]
    assert [f.code for f in apply(findings, categories=["DNS"])] == ["DNS_EXTERNAL_RESOLVER"]
    assert [f.code for f in apply(findings, categories=["Other"])] == ["NOT_A_RULE"]
    assert len(apply(findings)) == 3


def test_min_severity_drops_lower_findings() -> None:
    findings = [_finding("A", "critical"), _finding("B", "medium"), _finding("C", "info")]
    assert [f.code for f in apply(findings, min_severity="medium")] == ["A", "B"]


@requires_tshark
def test_dropped_findings_are_noted(tmp_path, cache_dir) -> None:
    from pcapforensics.pipeline import analyze

    report = analyze(FIXTURES / "weak_tls.pcap", tmp_path, categories=("Voice",)).report
    assert report.findings == []
    assert any(n.startswith("[policy] dropped") for n in report.notes)
