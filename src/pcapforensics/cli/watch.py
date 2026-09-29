"""``watch``: capture into a dumpcap ring buffer and report findings not seen before, file by file (issue #64)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import typer
from rich.markup import escape

from ..models import Finding, Report
from ..pipeline import analyze
from ._console import console

POLL_SECONDS = 1.0


def capture_argv(
    interface: str, ring: Path, seconds: int, files: int, which: Callable[[str], str | None] | None = None
) -> list[str] | None:
    """dumpcap ring-buffer command (tshark takes the same flags); None when neither is installed."""
    tool = next((path for path in map(which or shutil.which, ("dumpcap", "tshark")) if path), None)
    if tool is None:
        return None
    return [tool, "-i", interface, "-q", "-b", f"duration:{seconds}", "-b", f"files:{files}", "-w", str(ring / "ring.pcapng")]


class Watcher:
    """Analyze each ring file once it is closed; emit every finding id only the first time it appears."""

    def __init__(self, ring: Path, analyze_fn: Callable[[Path], Report], emit: Callable[[Finding, Path], None]) -> None:
        self.ring, self.analyze_fn, self.emit = ring, analyze_fn, emit
        self.done: set[str] = set()
        self.seen: set[str] = set()

    def closed(self, *, final: bool = False) -> list[Path]:
        # dumpcap numbers ring files (ring_00001_<time>.pcapng) and writes only the newest one.
        files = sorted(self.ring.glob("ring_*.pcap*"))
        return [p for p in (files if final else files[:-1]) if p.name not in self.done]

    def step(self, *, final: bool = False) -> int:
        new = 0
        for path in self.closed(final=final):
            self.done.add(path.name)
            for finding in self.analyze_fn(path).findings:
                if finding.id not in self.seen:
                    self.seen.add(finding.id)
                    self.emit(finding, path)
                    new += 1
        return new


def _emit(finding: Finding, path: Path) -> None:
    console.print(
        f"{datetime.now():%H:%M:%S} [bold]{finding.severity:<8}[/bold] {finding.code}  {escape(finding.title)}"
        f"  [dim]{path.name} · pcap-doctor why {finding.id[-16:]} --report {path.with_suffix('.pf-report')}/report.json[/dim]",
        highlight=False,
    )


def watch(
    interface: str = typer.Option(..., "--interface", "-i", help="capture interface (see `dumpcap -D`)"),
    seconds: int = typer.Option(60, "--seconds", min=5, help="close and analyze a ring file every N seconds"),
    files: int = typer.Option(10, "--files", min=2, help="ring files kept on disk"),
    ring_dir: Path = typer.Option(None, "--dir", file_okay=False, help="ring buffer directory (default: a temp dir)"),
) -> None:
    """Capture live traffic and print findings as they first appear (Ctrl-C to stop)."""
    ring = ring_dir or Path(tempfile.mkdtemp(prefix="pcap-doctor-watch-"))
    ring.mkdir(parents=True, exist_ok=True)
    argv = capture_argv(interface, ring, seconds, files)
    if argv is None:
        console.print("[red]watch needs dumpcap or tshark (install Wireshark / tshark)[/red]")
        raise typer.Exit(code=2)

    def analyze_file(path: Path) -> Report:
        return analyze(path, path.with_suffix(".pf-report"), use_cache=False).report

    watcher = Watcher(ring, analyze_file, _emit)
    console.print(f"watching {escape(interface)}: a ring file every {seconds}s in {ring} (Ctrl-C to stop)")
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        while proc.poll() is None:
            time.sleep(POLL_SECONDS)
            watcher.step()
    except KeyboardInterrupt:
        proc.terminate()
        proc.communicate()  # reaps the process and closes its pipes
    else:
        error = proc.communicate()[1].strip()
        console.print(f"[red]{argv[0]} exited with {proc.returncode}: {escape(error) or 'no error text'}[/red]")
        console.print("[red]capturing usually needs the wireshark/access_bpf group or root[/red]")
        raise typer.Exit(code=2) from None
    watcher.step(final=True)
    console.print(f"stopped: {len(watcher.seen)} distinct finding(s) in {len(watcher.done)} file(s); captures kept in {ring}")


def register(app: typer.Typer) -> None:
    app.command("watch")(watch)
