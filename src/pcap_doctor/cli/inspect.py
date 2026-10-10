"""Read-only inspection commands: flows, ciphers, detectors, suites, doctor, schema."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from ..data_ciphers import registry, registry_provenance
from ..index import IndexBuilder
from ..registry import all_detectors
from ..tshark import TsharkRunner, tshark_version
from ._console import console, tshark_errors


def flows(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    top: int = typer.Option(30, "--top", help="how many flows to print"),
) -> None:
    """Print the top conversations by volume."""
    with tshark_errors():
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


def ciphers(pcap: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Print the crypto matrix: sender -> recipient, suite, version, PFS."""
    with tshark_errors():
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


def doctor() -> None:
    """Check that the environment can run an analysis."""
    ok = True
    try:
        version = tshark_version()
        console.print(f"[green]tshark[/green] {version}")
    except Exception as exc:
        ok = False
        console.print(f"[red]tshark unavailable:[/red] {exc}")
    from ..tshark import default_prefs, valid_fields

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


def schema() -> None:
    """Print the machine-output schema (`--json` envelope) and the report.json schema version."""
    from ..models import SCHEMA_VERSION

    console.print(json.dumps({"schema": "doctor/1", "schema_version": SCHEMA_VERSION}, indent=2))


def register(app: typer.Typer) -> None:
    for command in (flows, ciphers, detectors, suites, doctor, schema):
        app.command()(command)
