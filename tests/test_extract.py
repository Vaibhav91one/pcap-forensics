"""File extraction from HTTP, FTP, SMB, TFTP, SMTP, IMAP and POP3 (issue #202)."""

from __future__ import annotations

import json
import stat
import sys

import pytest

from conftest import ROOT, fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.extract import (
    _imap_messages,
    _pop3_messages,
    _smtp_messages,
    _store,
    safe_name,
)

sys.path.insert(0, str(ROOT / "scripts"))
from parity_fixtures import FILE_PAYLOADS


@pytest.mark.parametrize(
    ("raw", "safe"),
    [("../../etc/passwd", "passwd"), ("..\\..\\boot.ini", "boot.ini"), ("%5cdocs%5carchive.zip", "archive.zip"),
     ("a\x1b[2Jb", "a_[2Jb"), ("", "file"), ("...", "file"), ("x" * 300, "x" * 120)],
)
def test_safe_name_is_one_harmless_component(raw: str, safe: str) -> None:
    assert safe_name(raw) == safe


def test_store_never_leaves_its_folder_and_never_overwrites(tmp_path) -> None:
    a = _store(tmp_path, "http", "../../evil.sh", data=b"1")
    b = _store(tmp_path, "http", "../../evil.sh", data=b"2")
    assert a.parent == b.parent == tmp_path / "http" and a != b and b.name == "evil.1.sh"
    assert not (a.stat().st_mode & (stat.S_IXUSR | stat.S_IRWXG | stat.S_IRWXO))


def test_mail_dialogue_parsers() -> None:
    assert _smtp_messages(b"EHLO x\r\nDATA\r\nSubject: a\r\n\r\n..dot\r\n.\r\nQUIT\r\n") == [b"Subject: a\r\n\r\n.dot\r\n"]
    server = b"+OK ready\r\n+OK\r\n+OK follows\r\nSubject: m\r\n\r\nbody\r\n.\r\n+OK bye\r\n"
    assert _pop3_messages(b"USER a\r\nRETR 1\r\nQUIT\r\n", server) == [b"Subject: m\r\n\r\nbody\r\n"]
    assert _imap_messages(b"* 1 FETCH (BODY[] {5}\r\nhello)\r\na2 OK\r\n") == [b"hello"]


@requires_tshark
def test_every_protocol_yields_the_bytes_that_were_sent(cli_runner, tmp_path, cache_dir) -> None:
    out = tmp_path / "files"
    result = cli_runner.invoke(app, ["extract", str(fixture("files_mix.pcap")), "-o", str(out)])
    assert result.exit_code == 0, result.output
    manifest = json.loads((out / "manifest.json").read_text())
    by = {(m["protocol"], m["name"].split("\\")[-1]): m for m in manifest}
    expect = {("http", "tool.exe"): "http", ("ftp-data", "report.pdf"): "ftp", ("tftp", "fw.bin"): "tftp",
              ("smb", "archive.zip"): "smb", ("smtp", "logo.png"): "mail", ("pop3", "pop-logo.png"): "mail",
              ("imap", "imap-logo.png"): "mail"}
    for key, payload in expect.items():
        assert (out / by[key]["path"]).read_bytes() == FILE_PAYLOADS[payload], key
        assert by[key]["size"] == len(FILE_PAYLOADS[payload])
    assert {m["kind"] for m in manifest if m["protocol"] == "smtp"} == {"message", "attachment"}


@requires_tshark
def test_protocol_subset_and_errors(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(fixture("files_mix.pcap"))
    out = tmp_path / "only"
    assert cli_runner.invoke(app, ["extract", pcap, "-o", str(out), "--protocols", "tftp"]).exit_code == 0
    assert [m["protocol"] for m in json.loads((out / "manifest.json").read_text())] == ["tftp"]
    assert cli_runner.invoke(app, ["extract", pcap, "-o", str(tmp_path / "x"), "--protocols", "gopher"]).exit_code == 2


@requires_tshark
def test_a_capture_with_no_files_gives_an_empty_manifest(cli_runner, tmp_path, cache_dir) -> None:
    out = tmp_path / "none"
    assert cli_runner.invoke(app, ["extract", str(fixture("syn_scan.pcap")), "-o", str(out)]).exit_code == 0
    assert json.loads((out / "manifest.json").read_text()) == []
