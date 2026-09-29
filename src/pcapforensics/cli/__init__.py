"""``pcap-doctor`` command line.

Every module in this package that defines ``register(app)`` adds its own commands, so a new
command is a new file and never an edit to a shared list (same idea as ``registry.py``).
"""

from __future__ import annotations

import importlib
import pkgutil
from importlib.metadata import version

import typer

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="pcap-doctor: offline pcap/pcapng triage. Who talked to whom, what crypto they negotiated, what is weak or leaking.",
)


def _print_version(requested: bool) -> None:
    if requested:
        typer.echo(f"pcap-doctor {version('pcap-doctor')}")
        raise typer.Exit()


@app.callback()
def main(
    show_version: bool = typer.Option(
        False, "--version", callback=_print_version, is_eager=True, help="Print the version and exit."
    ),
) -> None:
    """pcap-doctor: offline pcap/pcapng triage."""


def _load_commands() -> None:
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        register = getattr(module, "register", None)
        if callable(register):
            register(app)


_load_commands()
