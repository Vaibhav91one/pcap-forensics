"""``packets`` (the packet list) and ``packet`` (one frame: dissection tree + hex view). Issue #196."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from ..explorer import dissect, dissect_json, hexdump, list_packets
from ..prompts import clean_capture_text
from ._console import capture_cell, console, tshark_errors


def packets(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    display_filter: str = typer.Option(None, "--filter", "-Y", help="Wireshark display filter, e.g. 'tcp.port == 80'"),
    limit: int = typer.Option(200, "--limit", "-n", help="max packets to list (0 = all)"),
    as_json: bool = typer.Option(False, "--json", help="print the rows as JSON"),
) -> None:
    """List packets (frame, time, source, destination, protocol, length, info)."""
    with tshark_errors():
        rows = list_packets(pcap, display_filter, limit or None)
    if as_json:
        typer.echo(json.dumps([{k: clean_capture_text(v, 1000) if isinstance(v, str) else v
                                for k, v in r.as_dict().items()} for r in rows], indent=2))
        return
    table = Table(title=f"{len(rows)} packet(s) in {pcap.name}")
    for name in ("no.", "time", "source", "destination", "proto", "len", "info"):
        table.add_column(name, no_wrap=name != "info")
    for r in rows:
        table.add_row(str(r.frame), r.time, capture_cell(r.source), capture_cell(r.destination),
                      capture_cell(r.protocol), str(r.length), capture_cell(r.info))
    console.print(table)


def packet(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    frame: int = typer.Argument(..., help="frame number"),
    hex_view: bool = typer.Option(True, "--hex/--no-hex", help="append the hex view"),
    as_json: bool = typer.Option(False, "--json", help="the dissection tree as nested JSON (no hex view)"),
) -> None:
    """Dissect one frame: protocol tree and hex view."""
    with tshark_errors():
        if as_json:
            typer.echo(json.dumps(dissect_json(pcap, frame), indent=2))
            return
        tree = dissect(pcap, frame)
        dump = hexdump(pcap, frame) if hex_view else ""
    typer.echo("\n".join(clean_capture_text(line, 2000) for line in tree.splitlines()))
    if dump:
        typer.echo("\n" + dump)


def register(app: typer.Typer) -> None:
    app.command()(packets)
    app.command()(packet)
