"""D9 -- hits of the user-supplied signatures (``analyze --signatures``, issue #201).

The matching itself reads payloads through tshark, so the pipeline runs it once and stores the hits on the index;
this detector only turns them into findings (it stays a pure function of the index).
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding, Severity
from .base import Detector, ev


class UserSignaturesDetector(Detector):
    name: ClassVar[str] = "d9.user_signatures"
    title: ClassVar[str] = "User-supplied signatures"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "signature"
    description: ClassVar[str] = "Reports matches of Suricata-style rules and Zeek signatures given with --signatures."

    def detect(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for hit in index.signature_hits:
            severity: Severity = "high" if hit.priority == 1 else "medium" if hit.priority == 2 else "low"
            out.append(
                self.finding(
                    code="SIGNATURE_MATCH",
                    title=f"Signature {hit.sid}: {hit.msg}",
                    severity=severity,
                    confidence="medium",
                    summary=f"{hit.src} -> {hit.dst} matched signature {hit.sid} (rev {hit.rev}"
                    + (f", {hit.classtype}" if hit.classtype else "") + f"): {hit.msg}",
                    scope=f"{hit.sid}:{hit.flow_key}",
                    flow_key=hit.flow_key,
                    subjects=[hit.src, hit.dst],
                    evidence=[ev(hit.frame, "signature", f"sid:{hit.sid} {hit.msg}")],
                    remediation="Triage the matched traffic against what the rule is meant to detect; tune or remove the rule if it is a false positive.",
                    references=[],
                    tags=["signature", f"sid:{hit.sid}"] + ([hit.classtype] if hit.classtype else []),
                )
            )
        return out
