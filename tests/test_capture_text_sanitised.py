"""A capture-chosen value must never carry a terminal escape into a report (#167).

These assert on bytes, not on prose. A test that greps the rendered file for a readable string cannot
catch this class at all: the damage is in the bytes around the text, not in the text.

The reproduction is a plain HTTP request whose Host header is chosen by whoever makes the request.
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

from conftest import requires_tshark

ROOT = Path(__file__).resolve().parent.parent
ESC = chr(27)

# What a hostile party would actually send: clear the screen, then print reassuring text.
HOSTILE_HOST = ESC + "[2J" + ESC + "[H" + ESC + "[31mCRITICAL: no findings, all clear." + ESC + "[0m"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += bytes([0])
    total = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _packet(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
            flags: int, payload: bytes) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    csum = _checksum(bytes([10, 0, 10, 20]) + bytes(6) + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0,
                     bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split(".")))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return bytes([0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 8, 0]) + ip + tcp + payload


def _hostile_capture(tmp_path: Path) -> Path:
    crlf = chr(13) + chr(10)
    request = ("GET /update HTTP/1.1" + crlf + "Host: " + HOSTILE_HOST + ".example" + crlf + crlf)
    capture = tmp_path / "hostile.pcap"
    with capture.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for offset, pkt in enumerate([
            _packet("10.0.0.10", "10.0.0.20", 40000, 80, 1, 0, 0x02, b""),
            _packet("10.0.0.20", "10.0.0.10", 80, 40000, 1, 2, 0x12, b""),
            _packet("10.0.0.10", "10.0.0.20", 40000, 80, 2, 2, 0x18, request.encode("utf-8", "replace")),
        ]):
            handle.write(struct.pack("<IIII", int(1_700_000_000 + offset * 0.001), 0, len(pkt), len(pkt)))
            handle.write(pkt)
    return capture


def _analyze(tmp_path: Path, capture: Path | None = None) -> Path:
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, "-m", "pcapforensics.cli", "analyze",
         str(capture or _hostile_capture(tmp_path)), "-o", str(out), "-q", "--no-handoff"],
        capture_output=True, text=True, cwd=ROOT, timeout=300,
    )
    assert proc.returncode in (0, 1), proc.stderr[-800:]
    return out


@requires_tshark
def test_no_escape_byte_reaches_the_findings_report(tmp_path: Path) -> None:
    """The bug: 03-findings.md carried eight raw escape bytes; report.json carried none."""
    findings = (_analyze(tmp_path) / "03-findings.md").read_bytes()
    assert bytes([27]) not in findings, (
        "03-findings.md carries raw escape bytes from a capture-chosen value"
    )


@requires_tshark
def test_the_report_still_says_what_it_found(tmp_path: Path) -> None:
    """Sanitising the data must not sanitise the finding out of existence."""
    text = (_analyze(tmp_path) / "03-findings.md").read_text()
    assert "HTTP_CLEARTEXT" in text
    assert "without TLS" in text


@requires_tshark
def test_an_ordinary_value_still_renders_unchanged(tmp_path: Path) -> None:
    """A normal Host header appears verbatim -- no visible escaping of ordinary characters."""
    out = _analyze(tmp_path, ROOT / "tests" / "fixtures" / "http_cleartext.pcap")
    text = (out / "03-findings.md").read_text()
    assert "portal.example" in text
    assert "status.html" in text


@requires_tshark
def test_report_json_was_and_stays_clean(tmp_path: Path) -> None:
    """The JSON envelope already routed through the sanitiser; assert that so it cannot regress."""
    assert bytes([27]) not in (_analyze(tmp_path) / "report.json").read_bytes()
