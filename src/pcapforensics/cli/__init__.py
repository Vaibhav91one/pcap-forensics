"""``pcap-doctor`` command line.

Every module in this package that defines ``register(app)`` adds its own commands, so a new
command is a new file and never an edit to a shared list (same idea as ``registry.py``).
"""

from __future__ import annotations

import importlib
import pkgutil

import typer

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Offline pcap forensics.")


def _load_commands() -> None:
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        register = getattr(module, "register", None)
        if callable(register):
            register(app)


_load_commands()
