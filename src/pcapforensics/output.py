"""Machine-readable output built around the report: the JSON envelope and SARIF 2.1.0."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .models import SEVERITY_ORDER, Report
from .rules import CATEGORIES, RULES, category_of
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


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub code scanning ranks alerts by this CVSS-like score (a string); it maps >=9 critical, >=7 high, >=4 medium.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def sarif(report: Report, artifact_uri: str | None = None) -> dict[str, Any]:
    """One SARIF run: ruleId is the finding code, the fingerprint is the stable finding id.

    ``artifact_uri`` is the capture path as the user gave it (repo-relative in CI); the report's absolute
    path is the fallback. A capture is binary, so results carry no line region; frames go in properties.
    """
    uri = artifact_uri or report.capture.path
    codes = sorted({f.code for f in report.findings})
    index = {code: i for i, code in enumerate(codes)}
    worst: dict[str, str] = {}
    for f in report.findings:
        if f.code not in worst or SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[worst[f.code]]:
            worst[f.code] = f.severity
    rules = []
    for code in codes:
        rule = RULES.get(code)
        title = rule.title if rule else code
        rules.append(
            {
                "id": code,
                "name": code,
                "shortDescription": {"text": title},
                "defaultConfiguration": {"level": _LEVEL[worst[code]]},
                "properties": {
                    "category": category_of(code),
                    "tags": ["security", "network"],
                    "security-severity": _SECURITY_SEVERITY[worst[code]],
                },
            }
        )
    results = [
        {
            "ruleId": f.code,
            "ruleIndex": index[f.code],
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.summary}" if f.summary else f.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {"pcapDoctorFindingId/v1": f.id},
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "flow": f.flow_key,
                "frames": sorted({e.frame for e in f.evidence}),
            },
        }
        for f in report.findings
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pcap-doctor",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/Vaibhav91one/pcap-forensics",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
