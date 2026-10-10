"""``install``: teach coding agents to use pcap-doctor (Claude Code skill, Cursor rule, AGENTS.md block)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import typer

from ._console import console

AGENTS = ("claude", "cursor", "codex")
BEGIN = "<!-- pcap-doctor:begin (managed by `pcap-doctor install`) -->"
END = "<!-- pcap-doctor:end -->"


def guide() -> str:
    return (files("pcap_doctor") / "templates" / "agent-guide.md").read_text(encoding="utf-8")


def _skill() -> str:
    return (
        "---\nname: pcap-doctor\n"
        "description: Triage a pcap/pcapng capture with pcap-doctor and fix what it finds "
        "(weak TLS/SSH crypto, cleartext credentials, DNS, VoIP exposure).\n---\n\n" + guide()
    )


def _cursor_rule() -> str:
    return (
        "---\ndescription: Triage pcap/pcapng captures with pcap-doctor and fix what it finds\n"
        'globs: ["**/*.pcap", "**/*.pcapng"]\nalwaysApply: false\n---\n\n' + guide()
    )


def _write(path: Path, content: str, force: bool) -> bool:
    """Write `content`; an existing different file is kept unless `force`. Returns False when skipped."""
    if path.exists() and path.read_text(encoding="utf-8") != content and not force:
        console.print(f"[yellow]skipped {path}: it exists and differs (use --force to overwrite)[/yellow]")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    console.print(f"wrote {path}")
    return True


def _agents_block(path: Path) -> None:
    """Insert or replace the managed block in AGENTS.md; the rest of the file is untouched."""
    block = f"{BEGIN}\n{guide().rstrip()}\n{END}\n"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if BEGIN in text and END in text:
        head, rest = text.split(BEGIN, 1)
        text = head + block + rest.split(END, 1)[1].lstrip("\n")
    else:
        text = (text.rstrip("\n") + "\n\n" if text.strip() else "") + block
    path.write_text(text, encoding="utf-8")
    console.print(f"updated {path}")


def install(
    agent: list[str] = typer.Option(None, "--agent", help="claude, cursor or codex (repeatable; default: all)"),
    force: bool = typer.Option(False, "--force", help="overwrite skill/rule files that differ"),
    root: Path = typer.Option(Path("."), "--dir", help="project root to install into"),
) -> None:
    """Install the pcap-doctor guide for coding agents into this project."""
    chosen = agent or list(AGENTS)
    unknown = [a for a in chosen if a not in AGENTS]
    if unknown:
        console.print(f"[red]--agent: unknown value(s) {', '.join(unknown)}; valid: {', '.join(AGENTS)}[/red]")
        raise typer.Exit(code=2)
    ok = True
    if "claude" in chosen:
        ok &= _write(root / ".claude" / "skills" / "pcap-doctor" / "SKILL.md", _skill(), force)
    if "cursor" in chosen:
        ok &= _write(root / ".cursor" / "rules" / "pcap-doctor.mdc", _cursor_rule(), force)
    if "codex" in chosen:
        _agents_block(root / "AGENTS.md")
    raise typer.Exit(code=0 if ok else 1)


def register(app: typer.Typer) -> None:
    app.command("install")(install)
