"""``follow`` (one reassembled stream) and ``streams`` (the stream list). Issue #197."""

from __future__ import annotations

import json
import re
from pathlib import Path

import typer
from rich.table import Table

from ..follow import PROTOCOLS, list_streams
from ..follow import follow as follow_stream
from ..keymaterial import collect
from ._console import capture_cell, console, tshark_errors

_UNPRINTABLE = re.compile(rb"[^\x20-\x7e\r\n\t]")


def _ascii(data: bytes) -> str:
    """Printable text; every other byte becomes '.', so a hostile payload cannot drive the terminal."""
    return _UNPRINTABLE.sub(b".", data).decode("ascii").replace("\r\n", "\n").replace("\r", "\n")


def _hex(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {chunk.hex(' '):<47}  {text}")
    return "\n".join(lines)


def follow(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    proto: str = typer.Argument(..., help=f"one of {', '.join(PROTOCOLS)}"),
    stream: int = typer.Argument(..., help="stream number (see `streams`)"),
    mode: str = typer.Option("ascii", "--as", help="ascii | hex | raw (raw needs --out)"),
    direction: str = typer.Option("both", "--direction", help="both | client | server"),
    out: Path | None = typer.Option(None, "--out", "-o", help="write the reassembled payload to this file"),
    as_json: bool = typer.Option(False, "--json", help="segments as JSON (hex) instead of text"),
    tls_key: list[Path] | None = typer.Option(None, "--tls-key", exists=True, dir_okay=False, help="RSA private key to decrypt TLS"),
    keylog: Path | None = typer.Option(None, "--keylog", exists=True, dir_okay=False, help="TLS key log file"),
) -> None:
    """Follow one stream and show its reassembled payload (TCP, UDP, TLS, HTTP...)."""
    if mode not in ("ascii", "hex", "raw") or direction not in ("both", "client", "server"):
        console.print("[red]--as is ascii|hex|raw and --direction is both|client|server[/red]")
        raise typer.Exit(code=2)
    keys = collect(tls_key, keylog=keylog)
    try:
        with tshark_errors():
            followed = follow_stream(pcap, proto, stream, tuple(keys.tshark_args()))
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    if out is not None:
        out.write_bytes(followed.payload(direction))
        console.print(f"wrote {out} ({out.stat().st_size} bytes)")
        return
    if as_json:
        typer.echo(json.dumps({
            "proto": proto, "stream": stream, "node0": followed.node0, "node1": followed.node1,
            "segments": [{"from": "node1" if s.to_client else "node0", "hex": s.data.hex()} for s in followed.segments],
        }, indent=2))
        return
    if mode == "raw":
        console.print("[red]--as raw writes binary: pass --out FILE[/red]")
        raise typer.Exit(code=2)
    typer.echo(f"# {proto} stream {stream}: {followed.node0} -> {followed.node1} ({len(followed.segments)} segments)")
    if not followed.segments:
        typer.echo("# no application data (encrypted without a key? pass --tls-key or --keylog)")
    for seg in followed.segments:
        if (direction == "client" and seg.to_client) or (direction == "server" and not seg.to_client):
            continue
        typer.echo(f"--- {'server -> client' if seg.to_client else 'client -> server'} ({len(seg.data)} bytes)")
        typer.echo(_hex(seg.data) if mode == "hex" else _ascii(seg.data))


def streams(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    proto: str = typer.Option(None, "--proto", help="tcp | udp"),
) -> None:
    """List TCP/UDP streams and their numbers (the argument `follow` takes)."""
    with tshark_errors():
        rows = list_streams(pcap, proto)
    table = Table(title=f"{len(rows)} stream(s) in {pcap.name}")
    for name in ("proto", "stream", "a", "b", "packets", "bytes"):
        table.add_column(name, no_wrap=True)
    for r in rows:
        table.add_row(r.proto, str(r.index), capture_cell(r.endpoint_a), capture_cell(r.endpoint_b), str(r.packets), str(r.bytes))
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command()(follow)
    app.command()(streams)
