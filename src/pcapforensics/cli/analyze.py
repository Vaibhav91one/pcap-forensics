"""``analyze``: run the detectors on a capture and write the report."""

from __future__ import annotations

from pathlib import Path

import typer

from ..models import SEVERITY_ORDER
from ..pipeline import analyze
from ..policy import PolicyError, validate
from ..scoring import score
from ..tshark import TsharkMissingError
from ._console import console
from ._summary import render


def analyze_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True, help="pcap or pcapng file"),
    out: Path = typer.Option(None, "--out", "-o", help="output directory (default: <capture>.pf-report)"),
    only: list[str] = typer.Option(None, "--only", help="run only these detector ids (repeatable)"),
    category: list[str] = typer.Option(
        None, "--category", help="keep only findings in these categories (repeatable; see `rules`)"
    ),
    min_severity: str = typer.Option(
        None, "--min-severity", help="drop findings below this severity (critical|high|medium|low|info)"
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="exit non-zero when a finding at or above this severity exists (none|critical|high|medium|low|info)",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="ignore the tshark pass cache"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="suppress the console summary"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="list every finding, not the top 3 per category"),
    show_score: bool = typer.Option(False, "--score", help="print only the 0-100 health score"),
) -> None:
    """Analyze a capture and write the four report artifacts."""
    try:
        validate(only=only or (), categories=category or (), min_severity=min_severity, fail_on=fail_on)
    except PolicyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    try:
        result = analyze(
            pcap,
            out,
            only=tuple(only or ()),
            min_severity=min_severity,
            categories=tuple(category or ()),
            use_cache=not no_cache,
        )
    except TsharkMissingError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    if show_score:
        typer.echo(score(result.report.findings)[0])
    elif not quiet:
        render(console, result.report, verbose=verbose)
        console.print()
        for artifact in result.artifacts:
            console.print(f"  wrote {artifact}")
    threshold = None if fail_on == "none" else SEVERITY_ORDER.get(fail_on)
    tripped = (
        []
        if threshold is None
        else [f for f in result.report.findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]
    )
    if tripped and not (quiet or show_score):
        console.print(f"[red]{len(tripped)} finding(s) at or above {fail_on}; failing as requested[/red]")
    raise typer.Exit(code=1 if tripped else 0)


def register(app: typer.Typer) -> None:
    app.command("analyze")(analyze_cmd)
