"""``why``: explain one finding from a report: facts, evidence, fix, rule text, or a ready-made fix prompt."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.markdown import Markdown
from rich.markup import escape

from ..models import Finding, Report
from ..prompts import build_prompt, rule_text
from ._console import console


def _find_report(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    found = sorted(Path.cwd().glob("*.pf-report/report.json"))
    if len(found) != 1:
        where = "none" if not found else ", ".join(str(p) for p in found)
        console.print(f"[red]pass --report: found {len(found)} report(s) in the current directory ({where})[/red]")
        raise typer.Exit(code=2)
    return found[0]


def _match(report: Report, query: str) -> list[Finding]:
    """A frame number matches findings citing that frame; anything else is an id prefix (full or hash part)."""
    if query.isdigit():
        frame = int(query)
        return [f for f in report.findings if any(e.frame == frame for e in f.evidence)]
    return [f for f in report.findings if f.id.startswith(query) or f.id.rsplit(".", 1)[-1].startswith(query)]


def why(
    query: str = typer.Argument(..., help="finding id (or a prefix of it or of its hash), or a frame number"),
    report_path: Path = typer.Option(
        None, "--report", "-r", exists=True, dir_okay=False, help="report.json (default: the one *.pf-report here)"
    ),
    prompt: bool = typer.Option(False, "--prompt", help="print a fix prompt for a coding agent instead"),
) -> None:
    """Explain one finding: what was seen, the evidence, and how to fix it."""
    path = _find_report(report_path)
    report = Report.model_validate_json(path.read_text(encoding="utf-8"))
    matches = _match(report, query)
    if len(matches) != 1:
        hint = "give a longer id or a single frame" if matches else "check the frame number or id"
        console.print(f"[red]{len(matches)} finding(s) match {escape(query)!r}; {hint}[/red]")
        for finding in matches[:20]:
            console.print(f"  {finding.id}  {escape(finding.title)}", highlight=False)
        raise typer.Exit(code=2)
    finding = matches[0]
    if prompt:
        typer.echo(build_prompt(finding, report))
        return
    console.print(f"[bold]{finding.code}[/bold]  {finding.severity} · confidence {finding.confidence}")
    console.print(escape(finding.title), highlight=False)
    console.print(escape(finding.summary), highlight=False)
    for item in finding.evidence:
        console.print(f"  frame {item.frame}  {escape(item.field)} = {escape(item.value)}", highlight=False)
    if finding.remediation:
        console.print(f"[bold]fix[/bold] {escape(finding.remediation)}", highlight=False)
    if finding.references:
        console.print(f"[bold]references[/bold] {escape(', '.join(finding.references))}", highlight=False)
    console.print(Markdown(rule_text(finding.code)))


def register(app: typer.Typer) -> None:
    app.command("why")(why)
