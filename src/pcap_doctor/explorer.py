"""Per-packet explorer: the packet list, one frame's dissection tree, and its hex view (issue #196).

A read-only layer over the capture: every call asks tshark for exactly what was requested.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ondemand import run_fields, run_text
from .tshark import TsharkRunError


@dataclass(frozen=True)
class PacketRow:
    frame: int
    time: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str

    def as_dict(self) -> dict[str, object]:
        return {
            "frame": self.frame, "time": self.time, "source": self.source, "destination": self.destination,
            "protocol": self.protocol, "length": self.length, "info": self.info,
        }


_LIST_FIELDS = [
    "frame.number", "frame.time_relative", "_ws.col.Source", "_ws.col.Destination",
    "_ws.col.Protocol", "frame.len", "_ws.col.Info",
]


def list_packets(pcap: Path, display_filter: str | None = None, limit: int | None = None) -> list[PacketRow]:
    """The packet list. ``display_filter`` is a Wireshark display filter; a bad one raises ``TsharkRunError``."""
    extra = ["-c", str(limit)] if limit else None
    rows = []
    for r in run_fields(pcap, _LIST_FIELDS, display_filter, extra):
        rows.append(PacketRow(int(r[0]), r[1], r[2], r[3], r[4], int(r[5] or 0), r[6]))
    return rows


def _one_frame(frame: int) -> list[str]:
    if frame < 1:
        raise ValueError("frame numbers start at 1")
    return ["-Y", f"frame.number == {frame}"]


def dissect(pcap: Path, frame: int) -> str:
    """The full dissection tree of one frame, as Wireshark's packet-details pane prints it."""
    out = run_text(pcap, [*_one_frame(frame), "-V"])
    if not out.strip():
        raise TsharkRunError(f"no frame {frame} in {pcap.name}")
    return out


def hexdump(pcap: Path, frame: int) -> str:
    """Offset / hex / ASCII view of the frame bytes."""
    out = run_text(pcap, [*_one_frame(frame), "-x"])
    lines: list[str] = []
    for line in out.splitlines():
        if not (line[:4].strip() and all(c in "0123456789abcdef" for c in line[:4])):
            continue
        if line.startswith("0000") and lines:
            break  # a second dump is a decoded sub-buffer (decrypted, decompressed...), not the frame
        lines.append(line)
    if not lines:
        raise TsharkRunError(f"no frame {frame} in {pcap.name}")
    return "\n".join(lines)


def dissect_json(pcap: Path, frame: int) -> dict[str, Any]:
    """The same tree as nested JSON (tshark ``-T json``) for scripts."""
    parsed = json.loads(run_text(pcap, [*_one_frame(frame), "-T", "json"]) or "[]")
    if not parsed:
        raise TsharkRunError(f"no frame {frame} in {pcap.name}")
    first: dict[str, Any] = parsed[0]
    return first
