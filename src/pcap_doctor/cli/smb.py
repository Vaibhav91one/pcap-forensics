"""``smb``: users, shares and files seen in SMB/SMB2/SMB3 traffic. Issue #204."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from ..index import IndexBuilder
from ..tshark import TsharkRunner
from ._console import capture_cell, console, tshark_errors


def smb(pcap: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """List the NTLM identities, shares and files in SMB traffic (findings come from `analyze`)."""
    with tshark_errors():
        index = IndexBuilder(TsharkRunner(pcap)).build()
    users = Table(title="users (NTLM)")
    shares = Table(title="shares")
    files = Table(title="files")
    for table, cols in ((users, ("flow", "user", "domain", "workstation", "frame")), (shares, ("flow", "share", "frame")),
                        (files, ("flow", "file", "share", "frame"))):
        for col in cols:
            table.add_column(col, no_wrap=True)
    seen: set[tuple[str, ...]] = set()
    for op in index.smb:
        if op.user is not None and not op.response and op.command == "SESSION_SETUP":
            urow = (op.key, op.user or "(empty)", op.domain or "", op.host or "", str(op.frame))
            if urow not in seen:
                seen.add(urow)
                users.add_row(*(capture_cell(c) for c in urow))
        if op.command in ("TREE_CONNECT", "TREE_CONNECT_ANDX") and op.tree and not op.response:
            srow = (op.key, op.tree, str(op.frame))
            if srow not in seen:
                seen.add(srow)
                shares.add_row(*(capture_cell(c) for c in srow))
        if op.filename and op.command in ("CREATE", "NT_CREATE_ANDX") and ("file", op.key, op.filename) not in seen:
            seen.add(("file", op.key, op.filename))
            files.add_row(*(capture_cell(c) for c in (op.key, op.filename, op.share or "", str(op.frame))))
    for table in (users, shares, files):
        console.print(table)
    if not index.smb:
        console.print("no SMB traffic in this capture")


def register(app: typer.Typer) -> None:
    app.command()(smb)
