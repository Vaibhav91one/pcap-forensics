"""``query``: filter flows, hosts, protocol rows or findings with one expression. Issue #198."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from ..index import IndexBuilder
from ..query import SOURCES, QueryError, filter_rows, rows_of
from ..tshark import TsharkRunner
from ._console import capture_cell, console, tshark_errors

_COLUMNS = {
    "flows": ["endpoint_a", "port_a", "endpoint_b", "port_b", "app_proto", "packets", "bytes"],
    "findings": ["code", "severity", "scope", "title"],
}


def _cell(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:4])
    return "" if value is None else str(value)


def query(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    expression: str = typer.Argument(..., help='e.g. \'app_proto == "tls" and bytes > 10000\''),
    source: str = typer.Option("flows", "--source", "-s", help=f"one of: {', '.join(SOURCES)}"),
    limit: int = typer.Option(100, "--limit", "-n", help="max rows (0 = all)"),
    as_json: bool = typer.Option(False, "--json", help="matching rows as JSON"),
) -> None:
    """Filter analysed rows (flows, hosts, tls, http, dns, ssh, findings...) with a query expression.

    Fields are the row's own keys (see --json); `a.b` reaches nested keys. Operators: == != < <= > >=
    contains matches in {..}, and/or/not, parentheses; a CIDR on the right of == is a membership test.
    For raw frames use `packets -Y` (Wireshark display filter).
    """
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
    try:
        rows = filter_rows(rows_of(index, source), expression)
    except QueryError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    shown = rows[:limit] if limit else rows
    if as_json:
        typer.echo(json.dumps(shown, indent=2, default=str))
        return
    if not shown:
        console.print(f"0 {source} row(s) match")
        return
    keys = _COLUMNS.get(source) or list(shown[0])[:6]
    table = Table(title=f"{len(rows)} {source} row(s) match" + (f" (showing {len(shown)})" if len(shown) < len(rows) else ""))
    for k in keys:
        table.add_column(k, no_wrap=True)
    for r in shown:
        table.add_row(*(capture_cell(_cell(r.get(k))) for k in keys))
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command()(query)
