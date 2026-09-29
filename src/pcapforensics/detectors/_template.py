"""Copy this file, rename the class, delete what you do not need.

Checklist before you open a PR (all boxes are enforced in review):

- [ ] your detector lives in its own file and imports no sibling detector
- [ ] every finding has a stable ``code`` and a ``scope`` that is unique per flow
- [ ] every finding carries at least one :class:`Evidence` with a frame number
- [ ] you added a synthetic fixture under ``tests/fixtures/`` and a test
- [ ] you updated the detector table in ``README.md``
- [ ] ``make verify`` is green (ruff, mypy, pytest)
- [ ] you did **not** touch ``models.py``, ``index.py``, ``data_ciphers.py``
"""

from __future__ import annotations

from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev


class TemplateDetector(Detector):
    name: ClassVar[str] = "template"
    title: ClassVar[str] = "Template detector (delete me)"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "template"
    enabled: ClassVar[bool] = False  # disabled until the real work lands
    description: ClassVar[str] = "Scaffold showing the shape of a detector."

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        for flow in index.flows.values():
            if flow.app_proto != "example":
                continue
            findings.append(
                self.finding(
                    code="EXAMPLE_001",
                    title="Example finding title",
                    severity="low",
                    confidence="low",
                    summary="Replace with a real statement about the flow.",
                    scope=flow.key,
                    flow_key=flow.key,
                    subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[ev(flow.stream_index or 0, "frame.protocols", flow.app_proto)],
                    remediation="Delete this detector once you understand the pattern.",
                    references=["AGENTS.md"],
                    tags=["template"],
                )
            )
        return findings
