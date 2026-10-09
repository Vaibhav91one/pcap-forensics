"""Baseline diff: which findings are new compared with an earlier report.

A finding is known when the baseline has the same fingerprint: detector, code, title and flow key once every flow key's
client port is masked, because a re-capture of the same device picks new ephemeral ports (#126). Matching is by
fingerprint only (doctor-contract section 6).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding, Report, stable_id


@dataclass(frozen=True)
class Baseline:
    fingerprints: frozenset[str]
    detector_versions: dict[str, str]


def load_baseline(path: Path) -> Baseline:
    """Read a doctor/1 `--json`/`--json-out` envelope, or a report.json. Raises ValueError/OSError."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("not an object")
    if data.get("schema") == "doctor/1":
        found = {f["fingerprint"] for f in data["findings"]}
        versions = (data.get("data") or {}).get("detector_versions") or {}
        return Baseline(frozenset(found), versions)
    report = Report.model_validate(data)
    return Baseline(frozenset(map(finding_fingerprint, report.findings)), report.detector_versions)


#: ``proto:host:port<->host:port`` as built by ``models.flow_key`` (hosts may be IPv6, so split on the last colon)
_FLOW_KEY = re.compile(r"\b(tcp|udp|sctp):(\S+?):(\d+)<->(\S+):(\d+)")


def _mask_client_port(m: re.Match[str]) -> str:
    """The higher port of a flow is the client's ephemeral one; the lower is the service and stays."""
    # ponytail: "higher port = client" misreads a service above the client's port; use SYN direction if that bites
    proto, host_a, port_a, host_b, port_b = m.groups()
    if int(port_a) > int(port_b):
        port_a = "*"
    elif int(port_b) > int(port_a):
        port_b = "*"
    return f"{proto}:{host_a}:{port_a}<->{host_b}:{port_b}"


def _masked(text: str) -> str:
    return _FLOW_KEY.sub(_mask_client_port, text)


def finding_fingerprint(finding: Finding) -> str:
    """16 hex chars of the rule, detector, title and flow with the client's ephemeral port masked (doctor/1)."""
    # the flow key too: many titles name no host ("Client offers 4 prohibited suites")
    return stable_id(finding.detector, finding.code, _masked(finding.title), _masked(finding.flow_key or ""))


def new_since(baseline: Baseline, findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if finding_fingerprint(f) not in baseline.fingerprints]


def version_drift(baseline: Baseline, report: Report) -> list[str]:
    """Detectors whose version changed: their fingerprints may differ, so their findings can all look new."""
    old = baseline.detector_versions
    return sorted(name for name, ver in report.detector_versions.items() if name in old and old[name] != ver)
