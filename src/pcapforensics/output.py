"""Machine-readable output built around the report: the JSON envelope."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .models import Report
from .rules import CATEGORIES, category_of
from .scoring import score


def json_envelope(report: Report) -> dict[str, Any]:
    """Score, per-category counts and the full report; the report keeps its own schema_version."""
    value, label = score(report.findings)
    counts = Counter(category_of(f.code) for f in report.findings)
    return {
        "tool": "pcap-doctor",
        "version": report.tool_version,
        "score": value,
        "label": label,
        "categories": {name: counts[name] for name in CATEGORIES if counts[name]},
        "report": report.model_dump(mode="json"),
    }
