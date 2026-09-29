"""``ci install``: add a GitHub Actions workflow that reports and gates new pcap findings on pull requests."""

from __future__ import annotations

from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

import typer

from ..policy import SEVERITIES
from ._console import console
from .install import _write

ci = typer.Typer(help="CI integration.", no_args_is_help=True)
WORKFLOW = Path(".github") / "workflows" / "pcap-doctor.yml"


def workflow(captures: str, fail_on: str, ref: str) -> str:
    template = (files("pcapforensics") / "templates" / "workflow.yml").read_text(encoding="utf-8")
    return template.replace("__REF__", ref).replace("__CAPTURES__", captures).replace("__FAIL_ON__", fail_on)


@ci.command("install")
def install_workflow(
    captures: str = typer.Option(
        "**/*.pcap **/*.pcapng", "--captures", help="bash globstar patterns, space separated"
    ),
    fail_on: str = typer.Option("high", "--fail-on", help="gate severity for new findings (none|critical|high|medium|low|info)"),
    ref: str = typer.Option(None, "--ref", help="action ref to pin (default: this version's tag, v<version>)"),
    force: bool = typer.Option(False, "--force", help="overwrite a workflow that differs"),
    root: Path = typer.Option(Path("."), "--dir", help="repository root"),
) -> None:
    """Write .github/workflows/pcap-doctor.yml (GitHub Actions)."""
    valid = ("none", *SEVERITIES)
    if fail_on not in valid:
        console.print(f"[red]--fail-on: unknown value {fail_on}; valid: {', '.join(valid)}[/red]")
        raise typer.Exit(code=2)
    if not captures.strip() or any(ch in captures for ch in '"\n\\'):
        console.print("[red]--captures: give glob patterns without quotes, backslashes or newlines[/red]")
        raise typer.Exit(code=2)
    text = workflow(captures.strip(), fail_on, ref or f"v{version('pcap-doctor')}")
    raise typer.Exit(code=0 if _write(root / WORKFLOW, text, force) else 1)


def register(app: typer.Typer) -> None:
    app.add_typer(ci, name="ci")
