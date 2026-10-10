"""Stream follow: the reassembled payload of one TCP, UDP, TLS or HTTP stream (issue #197).

tshark does the reassembly (``-z follow,<proto>,raw,<n>``); this module parses its output into
directional segments so the CLI can show them as text, hex or raw bytes.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .ondemand import run_fields, run_text
from .tshark import TsharkRunError

PROTOCOLS = ("tcp", "udp", "tls", "dtls", "http", "http2", "quic", "sip")


@dataclass
class Segment:
    to_client: bool  # False: node 0 -> node 1 (the side that sent first)
    data: bytes


@dataclass
class FollowedStream:
    proto: str
    index: int
    node0: str = ""
    node1: str = ""
    segments: list[Segment] = field(default_factory=list)

    def payload(self, direction: str = "both") -> bytes:
        want = {"both": (False, True), "client": (False,), "server": (True,)}[direction]
        return b"".join(s.data for s in self.segments if s.to_client in want)


_NODE = re.compile(r"^Node ([01]): (.*)$")


def parse_follow(text: str, proto: str, index: int) -> FollowedStream:
    """Parse ``tshark -z follow,<proto>,raw,<n>`` output. A leading tab marks node 1 -> node 0 data."""
    stream = FollowedStream(proto, index)
    in_body = False
    for line in text.splitlines():
        if line.startswith("====="):
            in_body = False if stream.node1 and in_body else in_body
            continue
        node = _NODE.match(line)
        if node and not in_body:
            if node.group(1) == "0":
                stream.node0 = node.group(2)
            else:
                stream.node1 = node.group(2)
                in_body = True
            continue
        if in_body and line.strip():
            hexpart = line.strip()
            try:
                stream.segments.append(Segment(line.startswith("\t"), bytes.fromhex(hexpart)))
            except ValueError:
                continue
    return stream


def follow(pcap: Path, proto: str, index: int, decrypt_args: tuple[str, ...] = ()) -> FollowedStream:
    if proto not in PROTOCOLS:
        raise ValueError(f"unknown protocol {proto!r}; choose from {', '.join(PROTOCOLS)}")
    if index < 0:
        raise ValueError("stream numbers start at 0")
    out = run_text(pcap, [*decrypt_args, "-q", "-z", f"follow,{proto},raw,{index}"])
    stream = parse_follow(out, proto, index)
    if not stream.segments and stream.node0 in ("", ":0") and (proto in ("tcp", "udp") or not stream.node1.strip(":0")):
        hint = "" if proto in ("tcp", "udp") else " (encrypted? pass --tls-key or --keylog)"
        raise TsharkRunError(f"no stream {index} for {proto} in {pcap.name}{hint}")
    return stream


@dataclass
class StreamInfo:
    proto: str
    index: int
    endpoint_a: str
    endpoint_b: str
    packets: int
    bytes: int


def list_streams(pcap: Path, proto: str | None = None) -> list[StreamInfo]:
    """Every TCP and UDP stream with its endpoints; the number is what ``follow`` takes."""
    found: list[StreamInfo] = []
    for p in ("tcp", "udp"):
        if proto and proto != p:
            continue
        seen: dict[int, StreamInfo] = {}
        rows = run_fields(
            pcap,
            [f"{p}.stream", "ip.src", "ipv6.src", f"{p}.srcport", "ip.dst", "ipv6.dst", f"{p}.dstport", "frame.len"],
            f"{p}.stream",
        )
        counts: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        for r in rows:
            if not r[0].isdigit():
                continue
            i = int(r[0])
            counts[i][0] += 1
            counts[i][1] += int(r[7] or 0)
            if i not in seen:
                seen[i] = StreamInfo(p, i, f"{r[1] or r[2]}:{r[3]}", f"{r[4] or r[5]}:{r[6]}", 0, 0)
        for i, info in sorted(seen.items()):
            info.packets, info.bytes = counts[i]
            found.append(info)
    return found
