"""``pf`` command line."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .data_ciphers import registry, registry_provenance
from .index import IndexBuilder
from .models import SEVERITY_ORDER
from .pipeline import analyze
from .registry import all_detectors
from .tshark import TsharkMissingError, TsharkRunner, tshark_version

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Offline pcap forensics.")
console = Console()

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


@app.command()
def analyze_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True, help="pcap or pcapng file"),
    out: Path = typer.Option(None, "--out", "-o", help="output directory (default: <capture>.pf-report)"),
    only: list[str] = typer.Option(None, "--only", help="run only these detector ids (repeatable)"),
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
) -> None:
    """Analyze a capture and write the four report artifacts."""
    try:
        result = analyze(
            pcap,
            out,
            only=tuple(only or ()),
            min_severity=min_severity,
            use_cache=not no_cache,
        )
    except TsharkMissingError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    if not quiet:
        report = result.report
        console.print(f"[bold]capture[/bold] {report.capture.name}: {report.stats.packets:,} packets, "
                      f"{report.stats.flows} flows, {report.stats.hosts} hosts")
        table = Table(title=f"{len(report.findings)} finding(s)", show_lines=False)
        table.add_column("sev", no_wrap=True)
        table.add_column("code", no_wrap=True)
        table.add_column("title")
        table.add_column("conf", no_wrap=True)
        for finding in sorted(report.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))[:25]:
            style = SEVERITY_STYLE.get(finding.severity, "")
            table.add_row(
                f"[{style}]{finding.severity}[/{style}]",
                finding.code,
                finding.title,
                finding.confidence,
            )
        console.print(table)
        for artifact in result.artifacts:
            console.print(f"  wrote {artifact}")
    threshold = None if fail_on == "none" else SEVERITY_ORDER.get(fail_on)
    tripped = (
        []
        if threshold is None
        else [f for f in result.report.findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]
    )
    if tripped and not quiet:
        console.print(f"[red]{len(tripped)} finding(s) at or above {fail_on}; failing as requested[/red]")
    raise typer.Exit(code=1 if tripped else 0)


@app.command()
def flows(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    top: int = typer.Option(30, "--top", help="how many flows to print"),
) -> None:
    """Print the top conversations by volume."""
    index = IndexBuilder(TsharkRunner(pcap)).build()
    table = Table(title=f"{len(index.flows)} flows in {pcap.name}")
    table.add_column("conversation", no_wrap=True)
    table.add_column("app", no_wrap=True)
    table.add_column("packets", justify="right")
    table.add_column("bytes", justify="right")
    table.add_column("duration", justify="right")
    table.add_column("crypto")
    for flow in sorted(index.flows.values(), key=lambda f: -f.bytes)[:top]:
        table.add_row(
            f"{flow.endpoint_a}:{flow.port_a} <-> {flow.endpoint_b}:{flow.port_b}",
            flow.app_proto,
            f"{flow.packets:,}",
            f"{flow.bytes:,}",
            flow.duration_human,
            {True: "encrypted", False: "cleartext", None: "unknown"}[flow.encrypted],
        )
    console.print(table)


@app.command()
def ciphers(pcap: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Print the crypto matrix: sender -> recipient, suite, version, PFS."""
    index = IndexBuilder(TsharkRunner(pcap)).build()
    table = Table(title=f"{len(index.tls)} TLS sessions in {pcap.name}")
    table.add_column("conversation", no_wrap=True)
    table.add_column("proto", no_wrap=True)
    table.add_column("version", no_wrap=True)
    table.add_column("suite", no_wrap=True)
    table.add_column("PFS")
    table.add_column("SNI", no_wrap=True)
    for session in index.tls.values():
        table.add_row(
            session.server,
            session.proto,
            session.negotiated_version or "?",
            f"0x{session.chosen_cipher:04x}" if session.chosen_cipher else "?",
            {True: "yes", False: "NO", None: "?"}[session.forward_secrecy],
            session.sni or "-",
        )
    console.print(table)


@app.command()
def detectors() -> None:
    """List detectors and their versions."""
    table = Table(title="detectors")
    table.add_column("id", no_wrap=True)
    table.add_column("version", no_wrap=True)
    table.add_column("enabled")
    table.add_column("title")
    for detector in all_detectors():
        table.add_row(detector.name, detector.version, "yes" if detector.enabled else "no", detector.title)
    console.print(table)


@app.command()
def suites() -> None:
    """Print the cipher-suite registry summary and its policy provenance."""
    payload = registry()
    table = Table(title=f"{len(payload)} cipher suites in the registry")
    table.add_column("id", no_wrap=True)
    table.add_column("hex", no_wrap=True)
    table.add_column("name", no_wrap=True)
    table.add_column("kx", no_wrap=True)
    table.add_column("enc", no_wrap=True)
    table.add_column("policy", no_wrap=True)
    table.add_column("pfs")
    for suite in sorted(payload.values(), key=lambda s: s.id):
        table.add_row(
            str(suite.id), suite.hex, suite.name, suite.kx, suite.enc, suite.deprecation,
            "yes" if suite.forward_secrecy else "no",
        )
    console.print(table)
    for line in registry_provenance():
        console.print(f"  provenance: {line}")


@app.command()
def doctor() -> None:
    """Check that the environment can run an analysis."""
    ok = True
    try:
        version = tshark_version()
        console.print(f"[green]tshark[/green] {version}")
    except Exception as exc:
        ok = False
        console.print(f"[red]tshark unavailable:[/red] {exc}")
    from .tshark import default_prefs, valid_fields

    try:
        console.print(f"[green]fields[/green] {len(valid_fields())} known to this build")
        console.print(f"[green]prefs[/green]  {len(default_prefs())} known to this build")
    except Exception as exc:
        ok = False
        console.print(f"[red]field probe failed:[/red] {exc}")
    for detector in all_detectors():
        if not detector.enabled:
            console.print(f"[dim]skip {detector.name} (disabled)[/dim]")
    console.print("[green]ready[/green]" if ok else "[red]not ready[/red]")
    raise typer.Exit(code=0 if ok else 2)


@app.command()
def schema() -> None:
    """Print the JSON schema version of report.json."""
    from .models import SCHEMA_VERSION

    console.print(json.dumps({"schema_version": SCHEMA_VERSION}, indent=2))


# `pf analyze` reads better than `pf analyze-cmd`
app.command("analyze")(analyze_cmd)


if __name__ == "__main__":  # pragma: no cover
    app()
