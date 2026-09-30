"""Pipeline: capture -> index -> detectors -> artifacts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import policy
from .config import Config
from .config import apply as apply_config
from .index import CaptureIndex, IndexBuilder
from .models import SEVERITY_ORDER, ArtifactRef, Finding, Report
from .registry import enabled_detectors
from .render import markdown
from .tshark import TsharkRunner

ARTIFACT_NAMES = ("index.md", "01-flows.md", "02-ciphers.md", "03-findings.md", "04-diagrams.md", "report.json")


@dataclass
class RunResult:
    report: Report
    index: CaptureIndex
    outdir: Path
    artifacts: list[Path]

    @property
    def findings(self) -> list[Finding]:
        return self.report.findings

    def worst(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))[:10]


def analyze(
    pcap: Path,
    outdir: Path | None = None,
    *,
    only: tuple[str, ...] = (),
    min_severity: str | None = None,
    categories: tuple[str, ...] = (),
    use_cache: bool = True,
    config: Config | None = None,
    progress: Callable[[str], None] | None = None,
) -> RunResult:
    policy.validate(only=only, categories=categories, min_severity=min_severity)
    pcap = Path(pcap)
    outdir = Path(outdir or pcap.with_suffix(".pf-report"))
    outdir.mkdir(parents=True, exist_ok=True)

    runner = TsharkRunner(pcap, use_cache=use_cache)
    builder = IndexBuilder(runner)
    if progress:
        progress("Reading the capture with tshark")
    index = builder.build()

    detectors = enabled_detectors(include=only)
    findings: list[Finding] = []
    for detector in detectors:
        if progress:
            progress(f"Checking {detector.title}")
        try:
            found = detector.detect(index)
        except Exception as exc:  # one bad detector must not sink the run
            index.add_note(
                f"[{detector.name}] detector raised {type(exc).__name__}: {exc} -- other detectors still ran"
            )
            continue
        index.add_note(f"[{detector.name}] ran v{detector.version}: {len(found)} finding(s)")
        findings.extend(found)

    if config is not None:
        findings, config_notes = apply_config(findings, config)
        for note in config_notes:
            index.add_note(note)
    kept = policy.apply(findings, categories=categories, min_severity=min_severity)
    if len(kept) < len(findings):
        index.add_note(f"[policy] dropped {len(findings) - len(kept)} finding(s) outside the selected filters")
    findings = kept

    stats = builder.compute_stats(findings)
    report = Report(
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        capture=index.capture,
        stats=stats,
        flows=sorted(index.flows.values(), key=lambda f: -f.bytes),
        tls_sessions=sorted(index.tls.values(), key=lambda s: s.key),
        findings=findings,
        detector_versions={d.name: d.version for d in detectors},
        notes=list(index.notes),
    )
    report.artifacts = [
        ArtifactRef(name=name, path=str(outdir / name), kind="markdown" if name.endswith(".md") else "json")
        for name in ARTIFACT_NAMES
    ]

    artifacts = [
        markdown.render_flows(report, index),
        markdown.render_ciphers(report, index),
        markdown.render_findings(report, index),
        markdown.render_diagrams(report, index),
        markdown.render_json(report, outdir / "report.json"),
        markdown.render_index(report, index),
    ]
    return RunResult(report=report, index=index, outdir=outdir, artifacts=artifacts)
