"""On-demand tshark calls for the read-only inspection commands (packets, follow, ...).

The analysis pipeline runs fixed, cached passes (``tshark.py``). The explorer commands need one
frame, one stream or one user filter, so they call tshark directly. They share the decode
preferences of the passes (TCP desegmentation and so on) so a frame looks the same everywhere.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .tshark import TAB, TsharkRunError, _supported_prefs, tshark_path

Rows = list[list[str]]


def run_text(pcap: Path, args: list[str], *, timeout: int = 600, decode: bool = True, check: bool = True) -> str:
    """Run ``tshark -r pcap -n <args>`` and return stdout; a non-zero exit is a ``TsharkRunError`` unless ``check=False``."""
    cmd = [tshark_path(), "-r", str(pcap), "-n"]
    if decode:
        for pref in _supported_prefs():
            cmd += ["-o", f"{pref}:TRUE"]
    cmd += args
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=False, timeout=timeout)
    if check and proc.returncode != 0:
        raise TsharkRunError(f"tshark failed (exit {proc.returncode}):\n{proc.stderr.strip()[:2000]}\ncmd: {' '.join(cmd)}")
    return proc.stdout


def run_fields(pcap: Path, fields: list[str], display_filter: str | None = None, extra: list[str] | None = None) -> Rows:
    """Tab separated field values, one list per packet. Missing values are empty strings."""
    args = ["-T", "fields", "-E", f"separator={TAB}", "-E", "occurrence=a", "-E", "quote=n"]
    for field in fields:
        args += ["-e", field]
    if display_filter:
        args += ["-Y", display_filter]
    args += extra or []
    out = run_text(pcap, args)
    rows: Rows = []
    for line in out.splitlines():
        parts = line.split(TAB)
        rows.append(parts + [""] * (len(fields) - len(parts)))
    return rows
