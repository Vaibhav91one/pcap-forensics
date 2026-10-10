"""``extract``: write the files a capture carries (HTTP, FTP, SMB, TFTP, SMTP, IMAP, POP3) to disk. Issue #202."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from ..extract import PROTOCOLS, extract
from ..keymaterial import collect
from ._console import capture_cell, console, tshark_errors


def extract_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True),
    out: Path | None = typer.Option(None, "--out", "-o", help="output directory (default: CAPTURE.files)"),
    protocols: str = typer.Option("", "--protocols", help=f"comma-separated subset of: {', '.join(PROTOCOLS)}"),
    tls_key: list[Path] | None = typer.Option(None, "--tls-key", exists=True, dir_okay=False),
    keylog: Path | None = typer.Option(None, "--keylog", exists=True, dir_okay=False),
) -> None:
    """Extract transferred files (and mail attachments) into a directory with a manifest.json.

    The files are untrusted and may be malware: they are written 0600 and never executed or opened.
    """
    wanted = tuple(p.strip() for p in protocols.split(",") if p.strip()) or PROTOCOLS
    outdir = out or pcap.with_suffix(".files")
    keys = collect(tls_key, keylog=keylog)
    try:
        with tshark_errors():
            files = extract(pcap, outdir, wanted, tuple(keys.tshark_args()))
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    (outdir / "manifest.json").write_text(json.dumps([f.as_dict(outdir) for f in files], indent=2) + "\n", encoding="utf-8")
    table = Table(title=f"{len(files)} file(s) extracted to {outdir}")
    for name in ("protocol", "name", "size", "path"):
        table.add_column(name, no_wrap=True)
    for f in files:
        table.add_row(f.protocol, capture_cell(f.name), str(f.size), capture_cell(str(f.path.relative_to(outdir))))
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command("extract")(extract_cmd)
