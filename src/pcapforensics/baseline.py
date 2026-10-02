"""Baseline diff: which findings are new compared with an earlier report.

A finding is known when the baseline has the same id, or the same detector, code, title and flow key once every flow key's
client port is masked: a re-capture of the same device picks new ephemeral ports, and those are in the ids (#126).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, Report


def load_baseline(path: Path) -> Report:
    """Read a report.json, or a `--json`/`--json-out` envelope that wraps one. Raises ValueError/OSError."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("report"), dict):
        data = data["report"]
    return Report.model_validate(data)


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


def fingerprint(finding: Finding) -> tuple[str, str, str, str]:
    # the flow key too: many titles name no host ("Client offers 4 prohibited suites")
    return finding.detector, finding.code, _masked(finding.title), _masked(finding.flow_key or "")


def new_since(baseline: Report, findings: list[Finding]) -> list[Finding]:
    known_ids = {f.id for f in baseline.findings}
    known = {fingerprint(f) for f in baseline.findings}
    return [f for f in findings if f.id not in known_ids and fingerprint(f) not in known]


def version_drift(baseline: Report, report: Report) -> list[str]:
    """Detectors whose version changed: their ids may differ, so their findings can all look new."""
    old = baseline.detector_versions
    return sorted(name for name, ver in report.detector_versions.items() if name in old and old[name] != ver)
