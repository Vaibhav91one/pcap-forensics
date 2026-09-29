"""Console and styles shared by every command module."""

from __future__ import annotations

from rich.console import Console

console = Console()

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
