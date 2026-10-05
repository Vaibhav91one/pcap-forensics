"""Detector contract.

Rules of the game (enforced by review, documented in AGENTS.md):

* one detector == one file == one issue on the board,
* ``detect`` is a pure function of the :class:`CaptureIndex`,
* a detector never imports another detector,
* a detector never edits ``models.py`` / ``index.py`` / ``data_ciphers.py``,
* unknown input produces a finding or a note, never a silent pass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..index import CaptureIndex
from ..models import Confidence, Evidence, Finding, Severity
from ..prompts import CAPTURE_MODEL_LIMIT, clean_capture_text


def _model_text(value: str) -> str:
    # Every field a detector fills from the capture passes through here (#171).
    #
    # Captured text is attacker-controlled: an HTTP Host header, a DNS name, an SNI, a certificate
    # subject. It reached Finding.summary raw, so the model itself carried raw escape bytes and every
    # consumer inherited them -- the markdown renderer (#167) and the keys scan table (#169) each had
    # to be fixed separately. Filtering once, at the factory every detector builds its findings with,
    # closes the class instead of one call site at a time.
    #
    # Only capture-derived fields are filtered. remediation, references and tags are this project's
    # own text and are left exactly as written.
    return clean_capture_text(value, limit=CAPTURE_MODEL_LIMIT)


class Detector(ABC):
    name: ClassVar[str] = "unnamed"
    title: ClassVar[str] = "Unnamed detector"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "general"
    enabled: ClassVar[bool] = True
    description: ClassVar[str] = ""

    @abstractmethod
    def detect(self, index: CaptureIndex) -> list[Finding]:
        """Return findings. Must not raise on odd input; degrade to notes."""

    # -- helpers ------------------------------------------------------------
    def finding(
        self,
        *,
        code: str,
        title: str,
        severity: Severity,
        confidence: Confidence,
        summary: str,
        scope: str,
        category: str | None = None,
        evidence: list[Evidence] | None = None,
        subjects: list[str] | None = None,
        flow_key: str | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Finding:
        return Finding.make(
            detector=self.name,
            code=code,
            title=_model_text(title),
            severity=severity,
            confidence=confidence,
            category=category or self.category,
            summary=_model_text(summary),
            scope=_model_text(scope),
            evidence=[
                Evidence(
                    frame=item.frame,
                    field=_model_text(item.field),
                    value=_model_text(item.value),
                )
                for item in (evidence or [])
            ],
            subjects=[_model_text(item) for item in (subjects or [])],
            flow_key=_model_text(flow_key) if flow_key else None,
            remediation=remediation,
            references=references or [],
            tags=tags or [],
        )

    def note(self, index: CaptureIndex, text: str) -> None:
        index.add_note(f"[{self.name}] {text}")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Detector {self.name} v{self.version}>"


def ev(frame: int, field: str, value: object) -> Evidence:
    return Evidence(frame=frame, field=field, value=str(value)[:200])
