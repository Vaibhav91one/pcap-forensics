"""Interactive results after a scan, modelled on React Doctor (issue #98).

Home: score header, then Review findings · Add to GitHub Actions · Hand off to an agent (arrow keys).
Review: findings grouped by category with the selected one's impact, evidence, fix and rule guide below;
enter copies it as a findings report, h hands it to an agent. Hand off: an installed agent, or copy/show the
findings report or the fix prompt; a launch always shows the prompt first. Only in a real terminal: pipes, files, CI, --json, -q and
--score keep their exact output. The browser is a pure state machine (``handle(key)``/``render()``) so it is
tested without a terminal; ``browse()`` adds the key reader and the live display.
"""

from __future__ import annotations

import os
import sys
import textwrap
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.rule import Rule
from rich.text import Text

from ..clipboard import OSC52
from ..handoff import Agent, launch_argv
from ..models import SEVERITY_ORDER, Finding, Report
from ..output import findings_report
from ..prompts import build_prompt, build_report_prompt
from ..rules import CATEGORIES, CATEGORY_IMPACT, category_of
from ..scoring import score
from .ci import WORKFLOW, workflow

UP, DOWN, ENTER, ESC, LEFT, RIGHT = "up", "down", "enter", "esc", "left", "right"
PGUP, PGDN, HOME, END = "pgup", "pgdn", "home", "end"
LIST_ROWS = 12
EVIDENCE_ROWS = 5
ICON = {"critical": ("✖", "bold red"), "high": ("✖", "red"), "medium": ("⚠", "yellow"), "low": ("•", "cyan"), "info": ("ℹ", "dim")}
FACE = {"good": "^ ^", "needs work": "o o", "critical": "x x"}
BAR_STYLE = {"good": "green", "needs work": "yellow", "critical": "red"}


@dataclass
class Launch:
    """Leave the screen and run this agent command (the browser is done)."""

    argv: list[str]


@dataclass
class Screen:
    name: str
    cursor: int = 0
    finding: Finding | None = None  # hand off / prompt for one finding (None = the whole report)
    agent: Agent | None = None
    text: str = ""  # prompt, findings report or workflow shown on a text screen
    offset: int = 0  # first visible row of that text (it scrolls, #104)
    what: str = ""  # what that text is, for messages and the saved file's name


@dataclass
class Browser:
    report: Report
    agents: list[Agent]
    copy: Callable[[str], str]  # returns how it was copied: a tool name, OSC52 or "" (see clipboard.copy)
    write_workflow: Callable[[], str]
    save: Callable[[str, str], Path]  # (file name, text) -> where it was saved
    safe: bool = False
    screen: Screen = field(default_factory=lambda: Screen("home"))
    stack: list[Screen] = field(default_factory=list)
    read: set[str] = field(default_factory=set)
    flash: str = ""
    _page: int = 1  # rows of text visible on the last draw (page size for scrolling)
    _max_offset: int = 0

    def __post_init__(self) -> None:
        by_category: dict[str, list[Finding]] = {}
        for f in self.report.findings:
            by_category.setdefault(category_of(f.code), []).append(f)
        self.ordered: list[Finding] = []
        for category in CATEGORIES:
            self.ordered += sorted(by_category.get(category, []), key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.code))
        self.value, self.label = score(self.report.findings)
        self.potential, _ = score([f for f in self.report.findings if f.severity not in ("critical", "high")])

    # -- choices per screen ------------------------------------------------------------------------------
    def choices(self) -> list[tuple[str, str]]:
        name = self.screen.name
        if name == "home":
            items = [("review", f"Review {len(self.ordered)} finding(s)")] if self.ordered else []
            items.append(("ci", "Add to GitHub Actions (Recommended)"))
            if self.ordered:
                items.append(("handoff", "Hand off to an agent"))
            return items
        if name == "handoff":
            return [
                *((f"agent:{i}", a.name) for i, a in enumerate(self.agents)),
                ("copyreport", "Copy findings report"),
                ("showreport", "Show findings report"),
                ("copy", "Copy fix prompt"),
                ("show", "Show fix prompt"),
            ]
        if name == "ci":
            return [("write", f"Yes, write {WORKFLOW.as_posix()}"), ("show", "Show the workflow")]
        if name == "confirm":
            return [("launch", f"Launch {self.screen.agent.name if self.screen.agent else ''}"), ("copy", "Copy fix prompt instead")]
        return []

    # -- keys ---------------------------------------------------------------------------------------------
    def handle(self, key: str) -> Launch | str | None:
        """Return "quit", a Launch to run, or None to redraw."""
        self.flash = ""
        if key == "q":
            return "quit"
        if key in (ESC, LEFT):
            if not self.stack:
                return "quit" if self.screen.name == "home" and key == ESC else None
            self.screen = self.stack.pop()
            return None
        if self.screen.name == "review":
            return self._review_key(key)
        if self.screen.name in ("text", "confirm") and self._scroll(key):
            return None
        if self.screen.name == "text":
            if key == "c":
                self._copy(self.screen.text, self.screen.what)
            elif key == "s":
                self._save(self.screen.text, self.screen.what)
            return None
        items = self.choices()
        if key in (UP, "k"):
            self.screen.cursor = (self.screen.cursor - 1) % len(items)
        elif key in (DOWN, "j"):
            self.screen.cursor = (self.screen.cursor + 1) % len(items)
        elif key in (ENTER, RIGHT):
            return self._select(items[self.screen.cursor][0])
        return None

    def _scroll(self, key: str) -> bool:
        """Scroll a text screen; on the confirm screen ↑/↓ stay for the choices. True when the key scrolled."""
        page = max(1, self._page)
        text_only = self.screen.name == "text"
        step = {PGDN: page, " ": page, PGUP: -page, "b": -page}
        if text_only:
            step |= {DOWN: 1, "j": 1, UP: -1, "k": -1}
        if key in (HOME, "g"):
            self.screen.offset = 0
        elif key == END:
            self.screen.offset = self._max_offset
        elif key in step:
            self.screen.offset = max(0, min(self._max_offset, self.screen.offset + step[key]))
        else:
            return False
        return True

    def _review_key(self, key: str) -> Launch | str | None:
        if key in (UP, "k"):
            self.screen.cursor = (self.screen.cursor - 1) % len(self.ordered)
        elif key in (DOWN, "j"):
            self.screen.cursor = (self.screen.cursor + 1) % len(self.ordered)
        elif key == ENTER:
            self._copy(findings_report(self.report, [self.current()]), "findings report")
        elif key == "h":
            self._push(Screen("handoff", finding=self.current()))
        self.read.add(self.current().id)
        return None

    def _select(self, choice: str) -> Launch | str | None:
        target = self.screen.finding
        if choice == "review":
            self._push(Screen("review"))
            self.read.add(self.current().id)
        elif choice == "ci":
            self._push(Screen("ci"))
        elif choice == "handoff":
            self._push(Screen("handoff"))
        elif choice == "write":
            self.flash = self.write_workflow()
            self.screen = self.stack.pop()
        elif choice == "show" and self.screen.name == "ci":
            self._push(Screen("text", text=workflow("**/*.pcap **/*.pcapng", "high", "v<version>"), what="workflow"))
        elif choice == "show":
            self._push(Screen("text", finding=target, text=self.prompt_for(target), what="fix prompt"))
        elif choice == "copy":
            self._copy(self.prompt_for(target), "fix prompt")
        elif choice == "showreport":
            self._push(Screen("text", finding=target, text=self.report_for(target), what="findings report"))
        elif choice == "copyreport":
            self._copy(self.report_for(target), "findings report")
        elif choice.startswith("agent:"):
            agent = self.agents[int(choice.split(":")[1])]
            self._push(Screen("confirm", finding=target, agent=agent, text=self.prompt_for(target)))
        elif choice == "launch" and self.screen.agent:
            return Launch(launch_argv(self.screen.agent, self.screen.text, safe=self.safe))
        return None

    def _push(self, screen: Screen) -> None:
        self.stack.append(self.screen)
        self.screen = screen

    def _copy(self, text: str, what: str) -> None:
        how = self.copy(text)
        if how and how != OSC52:
            self.flash = f"[green]✓ Copied the {what} ({how})[/green]"
            return
        path = self.save(_file_name(what), text)
        if how == OSC52:
            self.flash = f"[green]✓ Sent the {what} to your terminal's clipboard (OSC 52)[/green] · also saved to {escape(str(path))}"
        else:
            self.flash = (
                f"[yellow]No clipboard here: saved the {what} to {escape(str(path))}[/yellow] "
                "[dim](install wl-clipboard or xclip to copy directly)[/dim]"
            )

    def _save(self, text: str, what: str) -> None:
        self.flash = f"[green]✓ Saved the {what} to {escape(str(self.save(_file_name(what), text)))}[/green]"

    def report_for(self, finding: Finding | None) -> str:
        return findings_report(self.report, [finding] if finding else None)

    def current(self) -> Finding:
        return self.ordered[self.screen.cursor]

    def prompt_for(self, finding: Finding | None) -> str:
        return build_prompt(finding, self.report) if finding else build_report_prompt(self.report)

    # -- drawing ------------------------------------------------------------------------------------------
    def render(self, height: int = 45, width: int = 100) -> RenderableType:
        parts: list[RenderableType] = [self.header(compact=self.screen.name != "home")]
        name = self.screen.name
        if name == "review":
            parts += self._review(height)
        elif name in ("text", "confirm"):
            parts += self._text(height, width)
        else:
            parts += self._menu()
        if self.flash:
            parts.append(Text.from_markup(self.flash))
        parts.append(Text(self._keys(), style="dim"))
        return Group(*parts)

    def header(self, *, compact: bool = False) -> RenderableType:
        width = 50
        filled = round(width * self.value / 100)
        bar = Text("█" * filled, style=BAR_STYLE[self.label]) + Text("░" * (width - filled), style="dim")
        stats = self.report.stats
        lines = [
            Text.assemble("  ┌─────┐  ", (f"{self.value} / 100 {self.label}", "bold"), "  ·  ", escape(self.report.capture.name)),
            Text.assemble(f"  │ {FACE[self.label]} │  ", bar),
            Text(f"  │  ▭  │  pcap-doctor {self.report.tool_version} · {stats.packets:,} packets, {stats.flows} flows, {stats.hosts} hosts"),
            Text("  └─────┘"),
        ]
        if not compact and self.potential > self.value:
            lines.append(Text(f"  Potential score {self.potential} after priority fixes +{self.potential - self.value}"))
        return Group(*lines, Text(""))

    def _menu(self) -> list[RenderableType]:
        out: list[RenderableType] = []
        name = self.screen.name
        if name == "home" and not self.ordered:
            out.append(Text("  No findings. Absence of findings is not safety: see the notes in index.md.\n"))
        if name == "handoff":
            what = f"finding {self.screen.finding.code}" if self.screen.finding else f"all {len(self.ordered)} finding(s)"
            out.append(Text.from_markup(f"  [bold]Choose how to continue[/bold] · {escape(what)}"))
            if not self.agents:
                out.append(Text("  No agent found on PATH (claude, codex, cursor-agent): copy or show the report or prompt.", style="dim"))
            out.append(Text(""))
        if name == "ci":
            out.append(Text.from_markup("[bold]? Add pcap-doctor to GitHub Actions?[/bold]"))
            out.append(Text("  Checks every pull request that changes a capture: only findings new since the base branch"))
            out.append(Text("  fail it, one summary comment is kept up to date, and SARIF goes to code scanning.\n"))
        for i, (key, label) in enumerate(self.choices()):
            chosen = i == self.screen.cursor
            out.append(Text.from_markup(f"{'[bold cyan]❯[/bold cyan]' if chosen else '›'} {escape(label)}"))
            if chosen and key == "ci" and name == "home":
                out.append(Text("  Scan every pull request so new findings cannot sneak in while you fix the backlog.", style="dim"))
            if chosen and key.startswith("agent:") and not self.safe:
                out.append(Text("  Launches with its approval prompts skipped (--safe keeps them).", style="red"))
            out.append(Text(""))
        return out

    def _review(self, height: int) -> list[RenderableType]:
        out: list[RenderableType] = []
        counts = Counter(f.code for f in self.ordered)
        rows = max(3, min(LIST_ROWS, height - 32))  # keep the detail and the key footer on screen
        start = max(0, min(self.screen.cursor - rows // 2, len(self.ordered) - rows))
        shown_category = ""
        for i, f in enumerate(self.ordered[start : start + rows], start):
            category = category_of(f.code)
            if category != shown_category:
                out.append(Text(category, style="bold"))
                shown_category = category
            icon, style = ICON[f.severity]
            mark = "›" if i == self.screen.cursor else (" " if f.id in self.read else "•")
            times = f" ×{counts[f.code]}" if counts[f.code] > 1 else ""
            line = Text.assemble(f"{mark} ", (icon, style), f" {f.code}{times}  ", (f.title, "dim"))
            line.truncate(118, overflow="ellipsis")
            out.append(line)
        if len(self.ordered) > rows:
            out.append(Text(f"  … {len(self.ordered)} findings, ↑/↓ scrolls", style="dim"))
        out.append(Rule(style="dim"))
        out += finding_view(self.current())
        sev: Counter[str] = Counter(f.severity for f in self.ordered)
        summary = "  ".join(f"{sev[s]} {s}" for s in SEVERITY_ORDER if sev[s])
        unread = sum(1 for f in self.ordered if f.id not in self.read)
        out.append(Text(f"\n{len(self.ordered)} findings  {summary}  ·  finding {self.screen.cursor + 1}/{len(self.ordered)}"))
        out.append(Text(f"{unread} unread", style="dim"))
        return out

    def _text(self, height: int, width: int) -> list[RenderableType]:
        s = self.screen
        title = f"Prompt for {s.agent.name}" if s.name == "confirm" and s.agent else s.what.capitalize() or "Preview"
        # Wrap to the terminal first so every display row is one screen line: the footer can never be pushed off.
        wrap = max(20, width - 1)
        lines = [part for line in s.text.splitlines() for part in (textwrap.wrap(line, wrap, replace_whitespace=False,
                 drop_whitespace=False, subsequent_indent="  ") or [""])]
        fixed = 12 + (7 if s.name == "confirm" else 0)  # header, title, rules, position, flash, keys (+ choices)
        rows = max(5, height - fixed)
        self._page = rows
        self._max_offset = max(0, len(lines) - rows)
        s.offset = min(s.offset, self._max_offset)
        out: list[RenderableType] = [Text(title, style="bold"), Rule(style="dim")]
        out += [Text(line, style="") for line in lines[s.offset : s.offset + rows]]
        out.append(Rule(style="dim"))
        if len(lines) > rows:
            last = min(len(lines), s.offset + rows)
            where = "top" if s.offset == 0 else "end" if last == len(lines) else f"{round(100 * last / len(lines))}%"
            out.append(Text(f"lines {s.offset + 1}–{last} of {len(lines)} · {where}", style="dim"))
        if s.name == "confirm":
            if not self.safe:
                out.append(Text("It will run without asking before commands (--safe keeps approvals).", style="red"))
            out += self._menu()
        return out

    def _keys(self) -> str:
        if self.screen.name == "review":
            return "↑/↓ move · enter copy finding · h hand off · esc back · q quit"
        if self.screen.name == "text":
            return "↑/↓ PgUp/PgDn g/End scroll · c copy · s save · esc back · q quit"
        if self.screen.name == "confirm":
            return "↑/↓ move · enter select · PgUp/PgDn scroll · esc back · q quit"
        return "↑/↓ move · enter select · esc back · q quit" if self.stack else "↑/↓ move · enter select · q quit"


def finding_view(f: Finding) -> list[RenderableType]:
    icon, style = ICON[f.severity]
    category = category_of(f.code)
    out: list[RenderableType] = [
        Text.assemble((f"{icon} {f.code}", style + " bold"), "  ", f.title),
        Text(f"  {category} · {f.severity} · confidence {f.confidence}" + (f" · {f.flow_key}" if f.flow_key else ""), style="dim"),
        Text(""),
        Text.assemble(("  Impact ", "bold"), CATEGORY_IMPACT[category]),
    ]
    if f.summary:
        out.append(Text.assemble(("  Why    ", "bold"), f.summary))
    if f.evidence:
        out.append(Text("  Evidence", style="bold"))
        for e in f.evidence[:EVIDENCE_ROWS]:
            out.append(Text(f"    frame {e.frame}  {e.field} = {e.value}"))
        if len(f.evidence) > EVIDENCE_ROWS:
            out.append(Text(f"    +{len(f.evidence) - EVIDENCE_ROWS} more: pcap-doctor why {f.id}", style="dim"))
    if f.remediation:
        out.append(Text.assemble(("  Fix    ", "bold"), f.remediation))
    if f.references:
        out.append(Text.assemble(("  Refs   ", "bold"), ", ".join(f.references)))
    out.append(Text(f"  Rule guide: pcap-doctor rules explain {f.code}", style="dim"))
    return out


def _file_name(what: str) -> str:
    return {"findings report": "findings-report.md", "fix prompt": "fix-prompt.md"}.get(what, "pcap-doctor.txt")


# -- terminal plumbing --------------------------------------------------------------------------------------
def supported() -> bool:
    """Raw single-key input: termios on macOS/Linux, msvcrt on Windows."""
    try:
        import termios  # noqa: F401
    except ImportError:
        try:
            import msvcrt  # noqa: F401
        except ImportError:
            return False
    return True


_SEQUENCES = {"\x1b[A": UP, "\x1b[B": DOWN, "\x1b[C": RIGHT, "\x1b[D": LEFT, "\x1bOA": UP, "\x1bOB": DOWN,
              "\x1bOC": RIGHT, "\x1bOD": LEFT, "\x1b[H": HOME, "\x1b[F": END, "\x1bOH": HOME, "\x1bOF": END,
              "\x1b[5~": PGUP, "\x1b[6~": PGDN, "\x1b[1~": HOME, "\x1b[4~": END, "\x1b[7~": HOME, "\x1b[8~": END}
_SINGLE = {"\r": ENTER, "\n": ENTER, "\x1b": ESC, "\x03": "q", "G": END}  # G before lower-casing, as in less


def split_keys(chunk: str) -> list[str]:
    """Split raw terminal input into key names; a burst like ESC ESC or several arrows stays separate keys."""
    keys: list[str] = []
    i = 0
    while i < len(chunk):
        for size in (4, 3):
            if chunk[i : i + size] in _SEQUENCES:
                keys.append(_SEQUENCES[chunk[i : i + size]])
                i += size
                break
        else:
            keys.append(_SINGLE.get(chunk[i], chunk[i].lower()))
            i += 1
    return keys


def read_keys() -> Iterator[str]:
    """Yield key names from the terminal. The terminal stays in cbreak mode (keys arrive at once, output is
    unchanged) for the whole session and is restored when the generator is closed."""
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
        import msvcrt

        arrows = {"H": UP, "P": DOWN, "K": LEFT, "M": RIGHT, "I": PGUP, "Q": PGDN, "G": HOME, "O": END}
        while True:
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):
                yield arrows.get(msvcrt.getwch(), "")
            else:
                yield _SINGLE.get(ch, ch.lower())
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            chunk = os.read(fd, 64).decode(errors="ignore")
            if not chunk:
                return
            yield from split_keys(chunk)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def write_workflow_here(version: str) -> str:
    """The "Add to GitHub Actions" action: same file and rules as `pcap-doctor ci install`, at the repo root."""
    root = Path.cwd()
    for parent in (root, *root.parents):
        if (parent / ".git").exists():
            root = parent
            break
    path = root / WORKFLOW
    text = workflow("**/*.pcap **/*.pcapng", "high", f"v{version}")
    if path.exists():
        same = path.read_text(encoding="utf-8") == text
        return f"✓ {path} already set up" if same else f"[yellow]{path} exists and differs: pcap-doctor ci install --force[/yellow]"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return f"[green]✓ Wrote {path}: commit it to scan pull requests[/green]"


def browse(
    console: Console,
    report: Report,
    *,
    safe: bool,
    agents: list[Agent],
    copy: Callable[[str], str],
    run: Callable[[list[str]], int],
    keys: Iterable[str] | None = None,
    live: bool = True,
) -> None:
    """Run the browser until q; launch an agent after leaving the screen if one was chosen."""
    from rich.live import Live

    outdir = Path(next((a.path for a in report.artifacts if a.name == "report.json"), "report.json")).parent

    def save(name: str, text: str) -> Path:
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / name).write_text(text, encoding="utf-8")
        return outdir / name

    browser = Browser(
        report, agents=agents, copy=copy, write_workflow=lambda: write_workflow_here(report.tool_version), save=save, safe=safe
    )
    source = iter(keys) if keys is not None else read_keys()
    result: Launch | str | None = None
    try:
        if live:
            with Live(browser.render(console.height, console.width), console=console, screen=True, auto_refresh=False) as screen:
                for key in source:
                    result = browser.handle(key)
                    if result is not None:
                        break
                    screen.update(browser.render(console.height, console.width), refresh=True)
        else:
            console.print(browser.render(console.height, console.width))
            for key in source:
                result = browser.handle(key)
                if result is not None:
                    break
                console.print(browser.render(console.height, console.width))
    except KeyboardInterrupt:
        result = "quit"
    finally:
        close = getattr(source, "close", None)
        if close:
            close()  # restores the terminal mode
    if isinstance(result, Launch):
        console.print(f"[dim]$ {escape(' '.join(result.argv[:-1]))} <prompt>[/dim]")
        run(result.argv)

