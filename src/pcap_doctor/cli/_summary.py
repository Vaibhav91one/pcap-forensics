"""Console summary: the score line, then findings grouped by category in a fixed order."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape

from ..models import SEVERITY_ORDER, Finding, Report
from ..rules import CATEGORIES, category_of
from ..scoring import score
from ._console import SEVERITY_STYLE

TOP_PER_CATEGORY = 3


def _severity(finding: Finding) -> str:
    style = SEVERITY_STYLE.get(finding.severity, "")
    return f"[{style}]{finding.severity:<8}[/{style}]"


def render(console: Console, report: Report, *, verbose: bool = False) -> None:
    value, label = score(report.findings)
    console.print(
        f"[bold]capture[/bold] {escape(report.capture.name)}: {report.stats.packets:,} packets, "
        f"{report.stats.flows} flows, {report.stats.hosts} hosts"
    )
    console.print(f"[bold]Score {value}/100 · {label}[/bold]")
    if not report.findings:
        console.print("no findings")
        return
    grouped: dict[str, list[Finding]] = {}
    for finding in report.findings:
        grouped.setdefault(category_of(finding.code), []).append(finding)
    for category in CATEGORIES:
        findings = sorted(grouped.get(category, []), key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.code))
        if not findings:
            continue
        console.print(f"\n[bold]{category}[/bold]  {len(findings)} finding(s) · worst {findings[0].severity}")
        shown = findings if verbose else findings[:TOP_PER_CATEGORY]
        for finding in shown:
            # titles carry capture text: escape so "[...]" in a hostname cannot inject or break markup
            console.print(f"  {_severity(finding)} {finding.code}  {escape(finding.title)}", highlight=False)
        if len(shown) < len(findings):
            console.print(f"  [dim]+{len(findings) - len(shown)} more (--verbose shows all)[/dim]")
