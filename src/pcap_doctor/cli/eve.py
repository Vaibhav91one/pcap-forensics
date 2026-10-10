"""``eve``: Suricata EVE-compatible JSON events for SIEM ingest. Issue #200."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from ..eve import EVENT_TYPES, build_eve
from ..index import IndexBuilder
from ..tshark import TsharkRunner
from ._console import tshark_errors


def eve(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    out: Path | None = typer.Option(None, "--out", "-o", help="write eve.json here (default: stdout)"),
    types: str = typer.Option("", "--types", help=f"comma-separated subset of: {', '.join(EVENT_TYPES)}"),
) -> None:
    """Emit EVE JSON, one event per line: alert, flow, dns, http, tls, fileinfo."""
    wanted = tuple(x.strip() for x in types.split(",") if x.strip()) or EVENT_TYPES
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
        try:
            events = build_eve(index, wanted)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    lines = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events)
    if out is None:
        typer.echo(lines, nl=False)
    else:
        out.write_text(lines, encoding="utf-8")
        typer.echo(f"wrote {out} ({len(events)} events)")


def register(app: typer.Typer) -> None:
    app.command()(eve)
