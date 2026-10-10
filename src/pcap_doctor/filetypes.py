"""Hashes and MIME types of extracted files (issue #203).

``describe`` reads a file once and returns MD5, SHA-1, SHA-256 and a MIME type chosen by magic bytes (the
extension is only a fallback, because a peer controls the file name but not the content). The magic table is
deliberately short and explicit: it covers executables, archives, documents, images, media and scripts.
"""

from __future__ import annotations

import hashlib
import mimetypes
from dataclasses import dataclass
from pathlib import Path

#: (offset, signature, mime type). The first match wins, so more specific entries come first.
MAGIC: tuple[tuple[int, bytes, str], ...] = (
    (0, b"MZ", "application/vnd.microsoft.portable-executable"),
    (0, b"\x7fELF", "application/x-executable"),
    (0, b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    (0, b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
    (0, b"\xca\xfe\xba\xbe", "application/java-vm"),
    (0, b"dex\n", "application/vnd.android.dex"),
    (0, b"%PDF-", "application/pdf"),
    (0, b"PK\x03\x04", "application/zip"),
    (0, b"PK\x05\x06", "application/zip"),
    (0, b"\x1f\x8b", "application/gzip"),
    (0, b"BZh", "application/x-bzip2"),
    (0, b"\xfd7zXZ\x00", "application/x-xz"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (0, b"Rar!\x1a\x07", "application/vnd.rar"),
    (257, b"ustar", "application/x-tar"),
    (0, b"\x89PNG\r\n\x1a\n", "image/png"),
    (0, b"\xff\xd8\xff", "image/jpeg"),
    (0, b"GIF87a", "image/gif"),
    (0, b"GIF89a", "image/gif"),
    (0, b"BM", "image/bmp"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (0, b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (0, b"ID3", "audio/mpeg"),
    (0, b"OggS", "audio/ogg"),
    (0, b"fLaC", "audio/flac"),
    (4, b"ftyp", "video/mp4"),
    (0, b"\x1a\x45\xdf\xa3", "video/webm"),
    (0, b"hsqs", "application/x-squashfs"),
    (0, b"\x27\x05\x19\x56", "application/x-uboot-image"),
    (0, b"-----BEGIN ", "application/x-pem-file"),
    (0, b"#!", "text/x-script"),
    (0, b"<?xml", "text/xml"),
)


def sniff(head: bytes, name: str = "") -> str:
    """MIME type of ``head`` (the first bytes of a file), falling back to the name and then to text/binary."""
    for offset, sig, mime in MAGIC:
        if head[offset : offset + len(sig)] == sig:
            if mime == "application/zip":
                return _zip_flavour(head, name)
            return mime
    if head[:2] == b"RI" and head[8:12] == b"WAVE":
        return "audio/wav"
    lowered = head.lstrip().lower()
    if lowered.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script")):
        return "text/html"
    guess = mimetypes.guess_type(name)[0] if name else None
    if head and _is_text(head):
        if guess and guess.startswith("text/"):
            return guess
        return "application/json" if head.lstrip()[:1] in (b"{", b"[") and name.endswith(".json") else "text/plain"
    return guess or "application/octet-stream"


def _zip_flavour(head: bytes, name: str) -> str:
    lowered = name.lower()
    for ext, mime in ((".jar", "application/java-archive"), (".apk", "application/vnd.android.package-archive"),
                      (".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                      (".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")):
        if lowered.endswith(ext):
            return mime
    return "application/zip"


def _is_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(data) > 0.95


@dataclass(frozen=True)
class FileInfo:
    md5: str
    sha1: str
    sha256: str
    size: int
    mime_type: str


def describe(path: Path, name: str = "") -> FileInfo:
    md5, sha1, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()
    head = b""
    size = 0
    with path.open("rb") as fh:
        while block := fh.read(1 << 20):
            if not head:
                head = block[:512]
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
            size += len(block)
    return FileInfo(md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), size, sniff(head, name or path.name))
