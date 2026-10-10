"""Console and styles shared by every command module."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import typer
from rich.console import Console
from rich.markup import escape

from ..prompts import clean_capture_text
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
        if not any(word in str(exc) for word in ("filter", "no frame", "no stream")):  # a user mistake, not a bad capture
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

#: Long enough for a path or a certificate subject, short enough that one hostile value cannot turn a
#: table into a wall. The prompt caps harder on purpose: a table is read, not parsed.
CAPTURE_CELL_LIMIT = 400


def capture_cell(value: str) -> str:
    # Capture-chosen text on its way into a rich render.
    #
    # Two separate problems meet here, on the same string. Control characters are removed first,
    # because a raw escape moves the cursor and clears the screen (#169). Then the markup is escaped,
    # because rich renders cell strings as markup: a firmware file named [bold]x.pem displays as
    # x.pem, so the analyst reads a path that is not the file on disk -- no error, and nothing visibly
    # dropped (#174).
    #
    # The order matters. Escaped first, the backslash would sit in front of every tag the sanitiser
    # would otherwise have removed, and the two would fight over the same characters.
    return escape(clean_capture_text(value, limit=CAPTURE_CELL_LIMIT))
