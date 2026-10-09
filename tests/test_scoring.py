"""The health score is local, deterministic and counts each code once (issue #48)."""

from __future__ import annotations

from pcapforensics.models import Finding
from pcapforensics.scoring import score


def _finding(code: str, severity: str = "high", confidence: str = "high", scope: str = "s") -> Finding:
    return Finding.make(
        detector="d0.test", code=code, title=code, severity=severity, confidence=confidence,  # type: ignore[arg-type]
        category="test", summary="", scope=scope,
    )


def test_no_findings_scores_100() -> None:
    assert score([]) == (100, "good")


def test_one_certain_critical_costs_20() -> None:
    assert score([_finding("A", "critical")]) == (80, "needs work")


def test_a_code_counts_once_at_its_worst_severity() -> None:
    many = [_finding("A", "medium", scope=str(i)) for i in range(10)] + [_finding("A", "high", scope="x")]
    assert score(many) == score([_finding("A", "high")])


def test_confidence_scales_the_penalty() -> None:
    assert score([_finding("A", "high", "low")])[0] == 95


def test_info_findings_are_free() -> None:
    assert score([_finding("A", "info"), _finding("B", "info")])[0] == 100


def test_score_never_goes_below_zero() -> None:
    assert score([_finding(f"C{i}", "critical") for i in range(10)]) == (0, "critical")
