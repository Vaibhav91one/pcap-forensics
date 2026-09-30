"""Output built around the report: the JSON envelope, SARIF 2.1.0 and a Markdown findings report."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .models import SEVERITY_ORDER, Finding, Report
from .prompts import clean
from .rules import CATEGORIES, CATEGORY_IMPACT, RULES, category_of
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


REPORT_VALUE_LIMIT = 1000  # longer than the prompt's cap: a report keeps the whole description


def _cell(value: str) -> str:
    """Capture text inside a Markdown table cell: sanitised, and no pipe can split the cell."""
    return clean(value, limit=REPORT_VALUE_LIMIT).replace("|", "\\|")


def findings_report(report: Report, findings: list[Finding] | None = None) -> str:
    """A security-weakness report in Markdown for a ticket or a pentest write-up (#101).

    `findings` defaults to every finding; worst first. Capture strings are sanitised like the fix prompt:
    no control characters, no backticks, capped length.
    """
    chosen = sorted(findings if findings is not None else report.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    cap = report.capture
    value, label = score(report.findings)
    counts: Counter[str] = Counter(f.severity for f in chosen)
    by_severity = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]) or "none"
    lines = [
        f"# Security findings: {_cell(cap.name)}",
        "",
        f"- **Capture:** `{_cell(cap.name)}` (sha256 `{cap.sha256[:16]}`), {cap.packets:,} packets",
        f"- **Tool:** pcap-doctor {report.tool_version}, report generated {report.generated_at}",
        f"- **Score:** {value}/100 ({label}) · **Findings in this report:** {len(chosen)} ({by_severity})",
        "",
    ]
    if len(chosen) > 1:
        lines += ["| # | Severity | Finding | Affected |", "|---|---|---|---|"]
        for i, f in enumerate(chosen, 1):
            lines.append(f"| {i} | {f.severity.title()} | {f.code}: {_cell(f.title)} | {_cell(f.flow_key or ', '.join(f.subjects) or '-')} |")
        lines.append("")
    for i, f in enumerate(chosen, 1):
        category = category_of(f.code)
        lines += [
            f"## {i}. [{f.severity.upper()}] {f.code}: {_cell(f.title)}",
            "",
            f"- **Category:** {category} · **Severity:** {f.severity} · **Confidence:** {f.confidence}",
        ]
        if f.flow_key or f.subjects:
            affected = f"`{_cell(f.flow_key)}`" if f.flow_key else ""
            hosts = ", ".join(_cell(s) for s in f.subjects)
            lines.append(f"- **Affected:** {affected}{' · hosts: ' + hosts if hosts else ''}")
        lines.append(f"- **Impact:** {CATEGORY_IMPACT[category]}")
        if f.summary:
            lines.append(f"- **Description:** {_cell(f.summary)}")
        if f.evidence:
            lines.append("- **Evidence:**")
            lines += [f"  - frame {e.frame}: `{_cell(e.field)}` = `{_cell(e.value)}`" for e in f.evidence]
        if f.remediation:
            lines.append(f"- **Remediation:** {_cell(f.remediation)}")
        if f.references:
            lines.append(f"- **References:** {', '.join(_cell(r) for r in f.references)}")
        lines += [f"- **Finding id:** `{f.id}`", ""]
    lines.append("_A capture without a finding is not proof of safety: pcap-doctor only sees the traffic in this capture._")
    return "\n".join(lines) + "\n"
