"""Output built around the report: the JSON envelope, SARIF 2.1.0 and a Markdown findings report."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .baseline import Baseline, finding_fingerprint
from .models import SEVERITY_ORDER, Finding, Report
from .prompts import clean
from .rules import CATEGORIES, CATEGORY_IMPACT, RULES, category_of
from .scoring import MODEL, score


def _location(f: Finding) -> dict[str, str]:
    if f.flow_key:
        return {"kind": "flow", "ref": f.flow_key}
    if f.evidence:
        return {"kind": "frame", "ref": f"frame {f.evidence[0].frame}"}
    return {"kind": "none", "ref": ""}


def contract_finding(f: Finding, state: str | None = None) -> dict[str, Any]:
    """A finding in the doctor/1 shape; the old fields that have no contract key stay as extra keys."""
    out: dict[str, Any] = {
        "id": f.code,
        "fingerprint": finding_fingerprint(f),
        "severity": f.severity,
        "confidence": f.confidence,
        "category": category_of(f.code),
        "message": f.title,
        "location": _location(f),
        "evidence": [{"ref": f"frame {e.frame}", "value": f"{e.field} = {e.value}"} for e in f.evidence],
        "remedy": f.remediation,
        "detector": f.detector,
        "finding_id": f.id,  # the per-run id `why` takes
        "summary": f.summary,
        "flow_key": f.flow_key,
        "subjects": f.subjects,
        "references": f.references,
        "tags": f.tags,
    }
    if state is not None:
        out["baseline_state"] = state
    return out


def json_envelope(report: Report, exit_code: int = 0, baseline: Baseline | None = None) -> dict[str, Any]:
    """The doctor/1 envelope (docs/doctor-contract.md). The old report, minus its findings, is under ``data``.

    With a baseline, ``findings`` is every finding marked new or unchanged; the score stays the full report's.
    """
    value, label = score(report.findings)
    counts = Counter(category_of(f.code) for f in report.findings)
    known = baseline.fingerprints if baseline is not None else None
    items = [
        contract_finding(f, None if known is None else ("unchanged" if finding_fingerprint(f) in known else "new"))
        for f in report.findings
    ]
    items.sort(key=lambda i: (SEVERITY_ORDER[i["severity"]], i["id"], i["fingerprint"]))
    data = report.model_dump(mode="json", exclude={"findings"})
    data["categories"] = {name: counts[name] for name in CATEGORIES if counts[name]}
    envelope: dict[str, Any] = {
        "schema": "doctor/1",
        "tool": "pcap-doctor",
        "version": report.tool_version,
        "exit_code": exit_code,
        "score": {"value": value, "label": label, "model": MODEL, "coverage_gaps": 0},
        "findings": items,
        "data": data,
    }
    if known is not None:
        current = {i["fingerprint"] for i in items}
        envelope["baseline"] = {
            "new": sum(i["baseline_state"] == "new" for i in items),
            "unchanged": sum(i["baseline_state"] == "unchanged" for i in items),
            "fixed": len(known - current),
        }
    return envelope


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub code scanning ranks alerts by this CVSS-like score (a string); it maps >=9 critical, >=7 high, >=4 medium.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def sarif(report: Report, artifact_uri: str | None = None, score_of: list[Finding] | None = None) -> dict[str, Any]:
    """One SARIF run: ruleId is the finding code, the fingerprint is the stable finding id.

    ``artifact_uri`` is the capture path as the user gave it (repo-relative in CI); the report's absolute
    path is the fallback. A capture is binary, so results carry no line region; frames go in properties.
    """
    uri = artifact_uri or report.capture.path
    value, label = score(report.findings if score_of is None else score_of)
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
            "partialFingerprints": {"doctorFinding/v1": finding_fingerprint(f)},
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
                "properties": {"score": {"value": value, "label": label, "model": MODEL, "coverage_gaps": 0}},
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
