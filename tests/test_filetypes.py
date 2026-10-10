"""Hashes and magic-byte MIME typing of extracted files (issue #203)."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from conftest import ROOT, fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.filetypes import describe, sniff

sys.path.insert(0, str(ROOT / "scripts"))
from parity_fixtures import FILE_PAYLOADS


@pytest.mark.parametrize(
    ("head", "name", "mime"),
    [
        (b"MZ\x90\x00", "tool.txt", "application/vnd.microsoft.portable-executable"),  # content beats a lying name
        (b"\x7fELF\x02", "", "application/x-executable"),
        (b"%PDF-1.7", "a.bin", "application/pdf"),
        (b"PK\x03\x04", "x.jar", "application/java-archive"),
        (b"PK\x03\x04", "x.zip", "application/zip"),
        (b"\x1f\x8b\x08", "", "application/gzip"),
        (b"\x89PNG\r\n\x1a\n", "", "image/png"),
        (b"#!/bin/sh\n", "", "text/x-script"),
        (b"<!DOCTYPE html><p>", "", "text/html"),
        (b"hello world\n", "notes.txt", "text/plain"),
        (b"\x00\x01\x02\x03\xff\xfe", "blob", "application/octet-stream"),
        (b"\x00\x01\x02", "pic.jpg", "image/jpeg"),
        (b"", "", "application/octet-stream"),
    ],
)
def test_magic_beats_the_name_and_binary_is_not_text(head: bytes, name: str, mime: str) -> None:
    assert sniff(head, name) == mime


def test_describe_matches_hashlib(tmp_path) -> None:
    data = b"abc" * 500_000  # larger than one read block
    f = tmp_path / "f.bin"
    f.write_bytes(data)
    info = describe(f)
    assert (info.md5, info.sha1, info.sha256, info.size) == (
        hashlib.md5(data, usedforsecurity=False).hexdigest(), hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        hashlib.sha256(data).hexdigest(), len(data))


@requires_tshark
def test_manifest_files_log_and_eve_carry_the_hashes(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(fixture("files_mix.pcap"))
    out = tmp_path / "files"
    assert cli_runner.invoke(app, ["extract", pcap, "-o", str(out)]).exit_code == 0
    manifest = {(m["protocol"], m["name"].split("\\")[-1]): m for m in json.loads((out / "manifest.json").read_text())}
    http = manifest[("http", "tool.exe")]
    want = FILE_PAYLOADS["http"]
    assert http["sha256"] == hashlib.sha256(want).hexdigest() and http["md5"] == hashlib.md5(want, usedforsecurity=False).hexdigest()
    assert http["sha1"] == hashlib.sha1(want, usedforsecurity=False).hexdigest()
    assert http["mime_type"] == "application/vnd.microsoft.portable-executable"
    assert manifest[("ftp-data", "report.pdf")]["mime_type"] == "application/pdf"
    assert manifest[("smtp", "logo.png")]["mime_type"] == "image/png"
    assert manifest[("smtp", "message-1.eml")]["mime_type"] == "text/plain"

    logs = tmp_path / "logs"
    assert cli_runner.invoke(app, ["logs", pcap, "-o", str(logs), "--only", "files", "--format", "json"]).exit_code == 0
    rows = [json.loads(line) for line in (logs / "files.json.log").read_text().splitlines()]
    row = next(r for r in rows if r["filename"] == "tool.exe")
    assert row["sha256"] == http["sha256"] and row["seen_bytes"] == len(want) and row["source"] == "HTTP"
    assert row["tx_hosts"] == ["10.1.0.80"] and row["conn_uids"][0].startswith("C")

    events = [json.loads(x) for x in cli_runner.invoke(app, ["eve", pcap, "--types", "fileinfo"]).output.splitlines()]
    info = next(e["fileinfo"] for e in events if e["fileinfo"]["filename"] == "tool.exe")
    assert info["sha256"] == http["sha256"] and info["size"] == len(want) and info["magic"].endswith("portable-executable")
