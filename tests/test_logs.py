"""Zeek-style per-protocol logs (issue #199)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.logs import LOG_NAMES


def _tsv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    header: list[str] = []
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith("#fields"):
            header = line.split("\t")[1:]
        elif not line.startswith("#"):
            rows.append(dict(zip(header, line.split("\t"), strict=True)))
    return header, rows


@pytest.fixture(scope="module")
def logs_dir(tmp_path_factory, cache_dir):
    from typer.testing import CliRunner

    out = tmp_path_factory.mktemp("logs")
    result = CliRunner().invoke(app, ["logs", str(fixture("logs_mix.pcap")), "-o", str(out), "--format", "both"])
    assert result.exit_code == 0, result.output
    return out


@requires_tshark
def test_every_log_is_written_in_zeek_tsv_with_a_header(logs_dir) -> None:
    for name in LOG_NAMES:
        text = (logs_dir / f"{name}.log").read_text()
        lines = text.splitlines()
        assert lines[0] == "#separator \\x09" and f"#path\t{name}" in lines
        assert lines[-1].startswith("#close")
        fields = next(line for line in lines if line.startswith("#fields")).split("\t")[1:]
        types = next(line for line in lines if line.startswith("#types")).split("\t")[1:]
        assert len(fields) == len(types)


@requires_tshark
def test_conn_log_has_originator_state_and_service(logs_dir) -> None:
    _, rows = _tsv(logs_dir / "conn.log")
    smtp = next(r for r in rows if r["id.resp_p"] == "25")
    assert (smtp["id.orig_h"], smtp["id.orig_p"], smtp["id.resp_h"]) == ("10.0.0.50", "44000", "10.0.0.25")
    assert smtp["proto"] == "tcp" and smtp["service"] == "smtp" and smtp["conn_state"] == "SF"
    assert smtp["history"].startswith("ShA") and smtp["history"].endswith("FfA")
    assert int(smtp["orig_bytes"]) > 100 and int(smtp["resp_bytes"]) > 50
    smb = next(r for r in rows if r["id.resp_p"] == "445")
    assert smb["service"] == "smb"


@requires_tshark
def test_smtp_dhcp_smb_and_weird_logs(logs_dir) -> None:
    _, smtp = _tsv(logs_dir / "smtp.log")
    assert smtp[0]["mailfrom"] == "alice@example.com" and smtp[0]["rcptto"] == "bob@example.org"
    assert smtp[0]["subject"] == "quarterly numbers" and smtp[0]["helo"] == "pf-laptop"
    _, dhcp = _tsv(logs_dir / "dhcp.log")
    assert dhcp[0]["mac"] == "02:aa:bb:cc:dd:01" and dhcp[0]["host_name"] == "pf-laptop"
    assert dhcp[0]["assigned_addr"] == "10.0.0.50" and dhcp[0]["msg_types"] == "DISCOVER,OFFER,REQUEST,ACK"
    _, smb = _tsv(logs_dir / "smb.log")
    assert [r["command"] for r in smb][:2] == ["NEGOTIATE", "NEGOTIATE"]
    assert any(r["username"] == "alice" and r["domain"] == "CORP" for r in smb)
    assert any(r["filename"] == "windows\\\\temp\\\\payload.exe" or r["filename"].endswith("payload.exe") for r in smb)
    _, weird = _tsv(logs_dir / "weird.log")
    assert weird[0]["name"] == "malformed_packet_exception_occurred" and weird[0]["severity"] == "error"


@requires_tshark
def test_notice_log_carries_the_findings(logs_dir) -> None:
    _, notice = _tsv(logs_dir / "notice.log")
    assert sorted(r["note"] for r in notice) == [
        "CLEARTEXT_SERVICE", "SMB_ADMIN_SHARE_ACCESS", "SMB_EXECUTABLE_ON_SHARE", "SMB_SIGNING_NOT_REQUIRED"]


@requires_tshark
def test_json_logs_are_one_object_per_line_without_unset_fields(logs_dir) -> None:
    lines = (logs_dir / "conn.json.log").read_text().splitlines()
    first = json.loads(lines[0])
    assert isinstance(first["ts"], float) and "history" not in first  # a UDP flow has no TCP history: the key is absent
    assert all(json.loads(line)["uid"].startswith("C") for line in lines)


@requires_tshark
def test_ftp_log_never_contains_the_password(cli_runner, tmp_path, cache_dir) -> None:
    out = tmp_path / "ftp"
    assert cli_runner.invoke(app, ["logs", str(fixture("ftp_ldap_creds.pcap")), "-o", str(out), "--only", "ftp"]).exit_code == 0
    text = (out / "ftp.log").read_text()
    assert "pf-ftp-pw-7c2a" not in text
    _, rows = _tsv(out / "ftp.log")
    assert [(r["command"], r["arg"], r["reply_code"]) for r in rows] == [("USER", "admin", "331"), ("PASS", "<hidden>", "230")]


@requires_tshark
def test_ssl_http_dns_ssh_logs_come_from_the_index(cli_runner, tmp_path, cache_dir) -> None:
    out = tmp_path / "x"
    assert cli_runner.invoke(app, ["logs", str(fixture("dns_tunnel.pcap")), "-o", str(out), "--only", "dns"]).exit_code == 0
    _, dns = _tsv(out / "dns.log")
    assert dns[0]["qtype_name"] == "TXT" and dns[0]["query"].endswith(".tunnel.example")
    out2 = tmp_path / "y"
    assert cli_runner.invoke(app, ["logs", str(fixture("weak_tls.pcap")), "-o", str(out2), "--only", "ssl,x509"]).exit_code == 0
    _, ssl = _tsv(out2 / "ssl.log")
    assert ssl[0]["version"].startswith("TLS 1.0") and ssl[0]["server_name"] == "weak.example"
    _, x509 = _tsv(out2 / "x509.log")
    assert x509 and x509[0]["id"] in ssl[0]["cert_chain_fuids"]


@requires_tshark
def test_logs_are_query_sources_and_bad_names_exit_2(cli_runner) -> None:
    pcap = str(fixture("logs_mix.pcap"))
    rows = json.loads(cli_runner.invoke(app, ["query", pcap, 'conn_state == "SF"', "-s", "log:conn", "--json"]).output)
    assert sorted(r["id.resp_p"] for r in rows) == [25, 445]
    assert cli_runner.invoke(app, ["logs", pcap, "--only", "nope"]).exit_code == 2
    assert cli_runner.invoke(app, ["logs", pcap, "--format", "xml"]).exit_code == 2
