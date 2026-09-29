"""``rules list|explain``: browse the rule catalog and read what a code means and how to fix it."""

from __future__ import annotations

import difflib

import typer
from rich.markdown import Markdown
from rich.table import Table

from ..policy import PolicyError, validate
from ..prompts import rule_text
from ..rules import RULES
from ._console import console

rules_app = typer.Typer(no_args_is_help=True, help="Browse the rule catalog.")


@rules_app.command("list")
def list_rules(
    category: list[str] = typer.Option(None, "--category", help="only these categories (repeatable)"),
) -> None:
    """List every finding code with its category, detector and title."""
    try:
        validate(categories=category or ())
    except PolicyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    table = Table(title="pcap-doctor rules")
    for column in ("code", "category", "detector", "title"):
        table.add_column(column, no_wrap=column != "title")
    for rule in RULES.values():
        if not category or rule.category in category:
            table.add_row(rule.code, rule.category, rule.detector, rule.title)
    console.print(table)


@rules_app.command("explain")
def explain(code: str = typer.Argument(..., help="finding code, e.g. TLS_VERSION_DEPRECATED")) -> None:
    """What a code means, why it matters, how to fix and verify it."""
    code = code.upper()
    if code not in RULES:
        close = difflib.get_close_matches(code, list(RULES), n=3)
        hint = f"; did you mean {', '.join(close)}?" if close else "; see `pcap-doctor rules list`"
        console.print(f"[red]unknown rule {code}{hint}[/red]")
        raise typer.Exit(code=2)
    console.print(Markdown(rule_text(code)))


def register(app: typer.Typer) -> None:
    app.add_typer(rules_app, name="rules")
