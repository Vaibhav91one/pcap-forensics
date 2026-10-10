"""SMB / SMB2 / SMB3 dissection and the d10.smb detector (issue #204)."""

from __future__ import annotations

import json

from conftest import codes, fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.index import IndexBuilder
from pcap_doctor.tshark import TsharkRunner


def _index(name: str):
    return IndexBuilder(TsharkRunner(fixture(name), use_cache=False)).build()


@requires_tshark
def test_operations_carry_users_shares_files_and_signing(cache_dir) -> None:
    ops = _index("logs_mix.pcap").smb
    assert {o.version for o in ops} == {"SMB2"}
    assert [o.command for o in ops if not o.response][:3] == ["NEGOTIATE", "SESSION_SETUP", "SESSION_SETUP"]
    auth = next(o for o in ops if o.user)
    assert (auth.user, auth.domain, auth.host) == ("alice", "CORP", "PF-LAPTOP")
    neg = next(o for o in ops if o.command == "NEGOTIATE" and o.response)
    assert neg.sign_enabled is True and neg.sign_required is False
    assert any(o.tree == "\\\\10.0.0.30\\ADMIN$" for o in ops)
    assert any((o.filename or "").endswith("payload.exe") for o in ops)


@requires_tshark
def test_smb1_is_read_as_smb1(cache_dir) -> None:
    ops = _index("smb_attack.pcap").smb
    assert ops[0].version == "SMB1" and ops[0].command == "NEGOTIATE"
    assert "NT LM 0.12" in ops[0].dialects


@requires_tshark
def test_attack_shaped_capture_raises_each_smb_finding(analyze_capture) -> None:
    result = analyze_capture(fixture("smb_attack.pcap"))
    assert codes(result) >= {"SMB1_IN_USE", "SMB_SIGNING_NOT_REQUIRED", "SMB_NULL_SESSION", "SMB_ADMIN_SHARE_ACCESS",
                             "SMB_REMOTE_EXEC_PIPE", "SMB_EXECUTABLE_ON_SHARE"}
    exe = next(f for f in result.report.findings if f.code == "SMB_EXECUTABLE_ON_SHARE")
    assert exe.severity == "high" and exe.evidence[0].value == "PSEXESVC.exe" and "T1021.002" in " ".join(exe.references)
    pipe = {f.evidence[0].value for f in result.report.findings if f.code == "SMB_REMOTE_EXEC_PIPE"}
    assert pipe == {"PSEXESVC.exe", "svcctl"}


@requires_tshark
def test_ordinary_smb_is_not_an_attack(analyze_capture) -> None:
    got = codes(analyze_capture(fixture("files_mix.pcap")))
    assert "SMB_SIGNING_NOT_REQUIRED" in got
    assert not got & {"SMB1_IN_USE", "SMB_NULL_SESSION", "SMB_ADMIN_SHARE_ACCESS", "SMB_REMOTE_EXEC_PIPE", "SMB_EXECUTABLE_ON_SHARE"}


@requires_tshark
def test_smb_command_and_query_source(cli_runner) -> None:
    out = cli_runner.invoke(app, ["smb", str(fixture("logs_mix.pcap"))]).output
    flat = out.replace("\n", " ")
    assert "alice" in out and "CORP" in out and "ADMIN$" in flat and "payload.e" in flat
    rows = json.loads(cli_runner.invoke(app, ["query", str(fixture("smb_attack.pcap")), 'version == "SMB1"', "-s", "smb", "--json"]).output)
    assert rows and rows[0]["command"] == "NEGOTIATE"
    assert "no SMB traffic" in cli_runner.invoke(app, ["smb", str(fixture("http_basic.pcap"))]).output
