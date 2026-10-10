"""Local 0-100 health score (issue #48).

A pure function of the findings: no network, no telemetry. Each distinct finding code counts
once, at its worst severity, so one noisy flow cannot sink the score on its own.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import SEVERITY_ORDER, Finding

MODEL = "pcap/1"  # names the formula below; bump to pcap/2 when PENALTY, CONFIDENCE_WEIGHT or the rounding change
PENALTY: dict[str, int] = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
CONFIDENCE_WEIGHT: dict[str, float] = {"high": 1.0, "medium": 0.75, "low": 0.5}
#: (lowest score for the label, label), checked in order.
LABELS: tuple[tuple[int, str], ...] = ((90, "good"), (60, "needs work"), (0, "critical"))


def _weight(finding: Finding) -> float:
    return PENALTY[finding.severity] * CONFIDENCE_WEIGHT[finding.confidence]


def score(findings: Iterable[Finding]) -> tuple[int, str]:
    """Return ``(score, label)``; 100 means no findings that cost points."""
    worst: dict[str, Finding] = {}
    for finding in findings:
        current = worst.get(finding.code)
        if current is None or (SEVERITY_ORDER[finding.severity], -_weight(finding)) < (
            SEVERITY_ORDER[current.severity],
            -_weight(current),
        ):
            worst[finding.code] = finding
    value = max(0, min(100, round(100 - sum(_weight(f) for f in worst.values()))))
    label = next(name for floor, name in LABELS if value >= floor)
    return value, label
