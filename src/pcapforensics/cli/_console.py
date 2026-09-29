"""Console and styles shared by every command module."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import typer
from rich.console import Console
from rich.markup import escape

from ..tshark import TsharkMissingError, TsharkRunError

console = Console()


@contextmanager
def tshark_errors() -> Iterator[None]:
    """tshark missing, or failing on the capture, is bad input: exit 2 with the reason, never a traceback.

    Exit 1 is reserved for the --fail-on gate, so a broken capture must not look like a finding.
    """
    try:
        yield
    except TsharkMissingError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(code=2) from exc
    except TsharkRunError as exc:
        lines = [line for line in str(exc).splitlines() if line.strip() and not line.startswith("cmd:")]
        console.print(f"[red]{escape(' '.join(lines[:2]))}[/red]", highlight=False)
        console.print(
            "[red]the capture may be truncated or corrupt; `editcap <in> <out>` rewrites the complete packets"
            " of a truncated file[/red]"
        )
        raise typer.Exit(code=2) from exc

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
