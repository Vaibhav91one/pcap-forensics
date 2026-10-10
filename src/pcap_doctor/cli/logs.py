"""``logs``: write Zeek-style per-protocol logs (TSV or JSON) for a capture. Issue #199."""

from __future__ import annotations

from pathlib import Path

import typer

from ..index import IndexBuilder
from ..logs import LOG_NAMES, build_logs, write_logs
from ..tshark import TsharkRunner
from ._console import console, tshark_errors


def logs(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(None, "--out", "-o", help="output directory (default: CAPTURE.logs)"),
    fmt: str = typer.Option("tsv", "--format", "-f", help="tsv (Zeek's own format), json (one object per line) or both"),
    only: str = typer.Option("", "--only", help=f"comma-separated subset of: {', '.join(LOG_NAMES)}"),
) -> None:
    """Write conn, dns, http, ssl, x509, files, notice, weird, dhcp, ftp, smtp, ssh and smb logs."""
    if fmt not in ("tsv", "json", "both"):
        console.print("[red]--format is tsv, json or both[/red]")
        raise typer.Exit(code=2)
    names = tuple(n.strip() for n in only.split(",") if n.strip())
    outdir = out or pcap.with_suffix(".logs")
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
        try:
            tables = build_logs(index, names)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    files = write_logs(tables, outdir, fmt, index.capture.first_seen, index.capture.last_seen)
    for path in files:
        console.print(f"{path}  ({len(tables[path.name.split('.')[0]].rows)} rows)", highlight=False, markup=False)


def register(app: typer.Typer) -> None:
    app.command()(logs)
