"""Baseline diff: which findings are new compared with an earlier report (matched by stable finding id)."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Report


def load_baseline(path: Path) -> Report:
    """Read a report.json, or a `--json`/`--json-out` envelope that wraps one. Raises ValueError/OSError."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("report"), dict):
        data = data["report"]
    return Report.model_validate(data)


def new_since(baseline: Report, findings: list[Finding]) -> list[Finding]:
    known = {f.id for f in baseline.findings}
    return [f for f in findings if f.id not in known]


def version_drift(baseline: Report, report: Report) -> list[str]:
    """Detectors whose version changed: their ids may differ, so their findings can all look new."""
    old = baseline.detector_versions
    return sorted(name for name, ver in report.detector_versions.items() if name in old and old[name] != ver)
