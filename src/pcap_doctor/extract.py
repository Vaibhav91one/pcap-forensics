"""File extraction: HTTP, FTP, SMB, TFTP, SMTP, IMAP and POP3 bodies written to disk (issue #202).

HTTP, FTP data, SMB and TFTP objects are reassembled by tshark (``--export-objects``). Mail is parsed here from the
reassembled TCP stream, because tshark does not hand POP3 or IMAP messages to its mail dissector: the message is
cut out of the SMTP ``DATA``, POP3 ``RETR`` or IMAP ``FETCH`` exchange, written as ``.eml`` and split into its
attachments with the standard ``email`` package.

Extracted bytes are untrusted and may be malware. Names are reduced to a safe basename, every path is checked to
stay inside the output directory, files get mode 0600 (never executable) and nothing is ever opened or run.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import unquote

from .follow import follow
from .ondemand import run_text
from .tshark import TsharkRunError

TSHARK_PROTOCOLS = ("http", "ftp-data", "smb", "tftp", "dicom")
MAIL_PROTOCOLS = ("smtp", "pop3", "imap")
PROTOCOLS = (*TSHARK_PROTOCOLS, *MAIL_PROTOCOLS)
MAIL_PORTS = {"smtp": (25, 587, 2525), "pop3": (110,), "imap": (143,)}


@dataclass
class ExtractedFile:
    protocol: str
    name: str  # the name the peer used (decoded), for display
    path: Path
    size: int
    source: str = ""  # e.g. the HTTP host, the mail message it came from
    extra: dict[str, str] = field(default_factory=dict)

    def as_dict(self, base: Path) -> dict[str, object]:
        return {"protocol": self.protocol, "name": self.name, "path": str(self.path.relative_to(base)),
                "size": self.size, "source": self.source, **self.extra}


def safe_name(name: str, fallback: str = "file") -> str:
    """A single path component: no directories, no control characters, no leading dots."""
    name = unquote(name).replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "_", name).strip(" .")
    return name[:120] or fallback


def _store(outdir: Path, protocol: str, name: str, data: bytes | None = None, src: Path | None = None) -> Path:
    folder = outdir / protocol
    folder.mkdir(parents=True, exist_ok=True)
    base = safe_name(name)
    dest = folder / base
    n = 1
    while dest.exists():
        stem, dot, ext = base.rpartition(".")
        dest = folder / (f"{stem}.{n}.{ext}" if dot else f"{base}.{n}")
        n += 1
    if folder.resolve() not in dest.resolve().parents:
        raise ValueError(f"refusing to write outside {folder}: {dest}")
    if src is not None:
        shutil.copyfile(src, dest)
    else:
        dest.write_bytes(data or b"")
    os.chmod(dest, 0o600)
    return dest


# ------------------------------------------------------------------------------------------ tshark objects
def _tshark_objects(pcap: Path, protocol: str, outdir: Path, decrypt_args: tuple[str, ...]) -> list[ExtractedFile]:
    found: list[ExtractedFile] = []
    with tempfile.TemporaryDirectory() as tmp:
        # check=False: tshark 4.6 writes the tftp objects and then aborts while tearing down; the files are good.
        run_text(pcap, [*decrypt_args, "-q", "--export-objects", f"{protocol},{tmp}"], check=False)
        for item in sorted(Path(tmp).iterdir()):
            if item.is_file():
                shown = unquote(item.name)
                stored = _store(outdir, protocol, item.name, src=item)
                found.append(ExtractedFile(protocol, shown, stored, stored.stat().st_size))
    return found


# ------------------------------------------------------------------------------------------ mail
def _unstuff(data: bytes) -> bytes:
    return data.replace(b"\r\n..", b"\r\n.")


def _smtp_messages(client: bytes) -> list[bytes]:
    out = []
    for m in re.finditer(rb"(?:^|\r\n)DATA\r\n", client, re.I):
        end = client.find(b"\r\n.\r\n", m.end() - 2)
        if end >= 0:
            out.append(_unstuff(client[m.end() : end + 2]))
    return out


_MULTILINE = {b"RETR", b"TOP", b"LIST", b"UIDL", b"CAPA"}


def _pop3_messages(client: bytes, server: bytes) -> list[bytes]:
    """Walk the dialogue: the first server line is the greeting, then one response per client command."""
    out: list[bytes] = []
    pos = server.find(b"\r\n") + 2  # greeting
    for line in client.split(b"\r\n"):
        if not line or pos < 2 or pos >= len(server):
            continue
        cmd, _, arg = line.partition(b" ")
        cmd = cmd.upper()
        status_end = server.find(b"\r\n", pos)
        if status_end < 0:
            break
        status = server[pos:status_end]
        pos = status_end + 2
        if cmd in _MULTILINE and status.startswith(b"+OK") and not (cmd in (b"LIST", b"UIDL") and arg):
            end = server.find(b"\r\n.\r\n", pos - 2)
            if end < 0:
                break
            if cmd in (b"RETR", b"TOP"):
                out.append(_unstuff(server[pos : end + 2]))
            pos = end + 5
    return out


def _imap_messages(server: bytes) -> list[bytes]:
    out = []
    for m in re.finditer(rb"\* \d+ FETCH \([^{\r\n]*?BODY(?:\.PEEK)?\[[^\]]*\](?:<\d+>)? \{(\d+)\}\r\n", server, re.I):
        size = int(m.group(1))
        out.append(server[m.end() : m.end() + size])
    for m in re.finditer(rb"\* \d+ FETCH \([^{\r\n]*?RFC822 \{(\d+)\}\r\n", server, re.I):
        size = int(m.group(1))
        out.append(server[m.end() : m.end() + size])
    return out


def _split_message(raw: bytes, protocol: str, outdir: Path, stem: str) -> list[ExtractedFile]:
    found = []
    eml = _store(outdir, protocol, f"{stem}.eml", data=raw)
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(msg.get("subject", "") or "")
    found.append(ExtractedFile(protocol, eml.name, eml, eml.stat().st_size, subject, {"kind": "message"}))
    parts = msg.iter_attachments() if isinstance(msg, EmailMessage) else []
    for part in parts:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            continue
        name = part.get_filename() or "attachment"
        stored = _store(outdir, protocol, name, data=payload)
        found.append(ExtractedFile(protocol, name, stored, stored.stat().st_size, subject,
                                   {"kind": "attachment", "content_type": part.get_content_type(), "message": eml.name}))
    return found


def _streams_on(pcap: Path, ports: tuple[int, ...]) -> list[int]:
    from .ondemand import run_fields

    seen: dict[int, None] = {}
    for p in ports:
        for row in run_fields(pcap, ["tcp.stream"], f"tcp.port == {p} && tcp.len > 0"):
            if row[0].isdigit():
                seen.setdefault(int(row[0]))
    return sorted(seen)


def _mail(pcap: Path, protocol: str, outdir: Path, decrypt_args: tuple[str, ...]) -> list[ExtractedFile]:
    found: list[ExtractedFile] = []
    count = 0
    for stream in _streams_on(pcap, MAIL_PORTS[protocol]):
        try:
            followed = follow(pcap, "tcp", stream, decrypt_args)
        except TsharkRunError:
            continue
        client, server = followed.payload("client"), followed.payload("server")
        raws = (_smtp_messages(client) if protocol == "smtp"
                else _pop3_messages(client, server) if protocol == "pop3" else _imap_messages(server))
        for raw in raws:
            count += 1
            found += _split_message(raw, protocol, outdir, f"message-{count}")
    return found


# ------------------------------------------------------------------------------------------ public API
def extract(pcap: Path, outdir: Path, protocols: tuple[str, ...] = PROTOCOLS,
            decrypt_args: tuple[str, ...] = ()) -> list[ExtractedFile]:
    unknown = [p for p in protocols if p not in PROTOCOLS]
    if unknown:
        raise ValueError(f"unknown protocol(s) {', '.join(unknown)}; protocols: {', '.join(PROTOCOLS)}")
    outdir.mkdir(parents=True, exist_ok=True)
    found: list[ExtractedFile] = []
    for protocol in protocols:
        if protocol in TSHARK_PROTOCOLS:
            found += _tshark_objects(pcap, protocol, outdir, decrypt_args)
        else:
            found += _mail(pcap, protocol, outdir, decrypt_args)
    return found
