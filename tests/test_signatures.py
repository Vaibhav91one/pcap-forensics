"""Signature engine: Suricata rule subset and Zeek signatures (issue #201)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from conftest import ROOT, fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.signatures import RuleError, _content_ok, _flags_ok, load_rules, parse_suricata, parse_zeek

sys.path.insert(0, str(ROOT / "scripts"))

V = {"HOME_NET": "10.0.0.0/8", "EXTERNAL_NET": "any"}


def rule(text: str):
    return parse_suricata(text, V)


def test_parse_header_and_options() -> None:
    r = rule('alert tcp $HOME_NET any -> any [80,8080] (msg:"login"; content:"POST /login"; nocase; '
             'content:"|0d 0a|pass"; distance:0; within:200; pcre:"/word=\\w+/i"; flow:to_server,established; '
             'sid:100; rev:3; classtype:web-application-attack; priority:1;)')
    assert (r.sid, r.rev, r.msg, r.priority, r.severity()) == ("100", "3", "login", 1, "high")
    assert r.src == [(False, "10.0.0.0/8")] and r.dport == [(False, (80, 80)), (False, (8080, 8080))]
    assert r.contents[0].nocase and r.contents[1].pattern == b"\r\npass" and r.contents[1].within == 200
    assert r.to_server is True and len(r.pcre) == 1


@pytest.mark.parametrize(
    "text",
    [
        'alert tcp any any -> any any (msg:"x"; content:"a";)',  # no sid
        'alert tcp any any -> any any (msg:"x"; sid:1;)',  # nothing to match
        'alert tcp any any -> any any (msg:"x"; content:"a"; http_uri; sid:1;)',  # unsupported keyword
        'alert icmp any any -> any any (msg:"x"; content:"a"; sid:1;)',  # unsupported protocol
        'alert tcp $NOPE any -> any any (msg:"x"; content:"a"; sid:1;)',  # undefined variable
        'alert tcp any any -> any any (msg:"x"; content:"|zz|"; sid:1;)',  # bad hex
        "not a rule",
    ],
)
def test_unsupported_or_broken_rules_are_rejected_not_approximated(text: str) -> None:
    with pytest.raises(RuleError):
        rule(text)


def test_bad_rules_in_a_file_become_warnings(tmp_path: Path) -> None:
    f = tmp_path / "a.rules"
    f.write_text('# c\nalert tcp any any -> any any (msg:"ok"; content:"a"; sid:1;)\nalert tcp any any -> any any (msg:"no"; sid:2;)\n')
    rules, warnings = load_rules([f], V)
    assert [r.sid for r in rules] == ["1"] and len(warnings) == 1 and "a.rules:3" in warnings[0]


def test_content_positions_and_negation() -> None:
    r = rule('alert tcp any any -> any any (msg:"x"; content:"GET"; offset:0; depth:3; content:"/a"; distance:1; within:2; '
             'content:!"zzz"; sid:1;)')
    assert _content_ok(b"GET /a HTTP", r.contents)
    assert not _content_ok(b"GET  /a", r.contents)  # '/a' is 2 bytes away: outside distance 1 / within 2
    assert not _content_ok(b"XGET /a", r.contents)  # depth 3 from offset 0
    assert not _content_ok(b"GET /a zzz", r.contents)  # negated content present


def test_tcp_flag_matching() -> None:
    assert _flags_ok("S", 0x02) and not _flags_ok("S", 0x12)
    assert _flags_ok("S+", 0x12) and _flags_ok("SA", 0x12)


def test_zeek_signature() -> None:
    (r,) = parse_zeek('signature pf-login {\n ip-proto == tcp\n dst-port == 80\n payload /POST \\/login/\n event "login posted"\n}', V)
    assert r.proto == "tcp" and r.dport == [(False, (80, 80))] and r.msg == "login posted"
    with pytest.raises(RuleError):
        parse_zeek("signature s { tcp-state established\n payload /x/ }", V)


RULES = """
alert tcp any any -> any 80 (msg:"PF password in form"; content:"password="; content:"hunter"; distance:0; classtype:credential-theft; priority:1; sid:9100001; rev:2;)
alert tcp any 80 -> any any (msg:"PF response ok"; flow:to_client; content:"HTTP/1.1 200"; sid:9100002;)
alert tcp any any -> any 80 (msg:"PF wrong"; content:"not-in-capture"; sid:9100003;)
alert tcp any any -> any 443 (msg:"PF wrong port"; content:"password="; sid:9100004;)
pass tcp any 80 -> any any (msg:"PF allow"; content:"HTTP/1.1 200"; sid:9100005;)
alert tcp any any -> any any (msg:"PF unsupported"; content:"a"; http_uri; sid:9100006;)
"""


@requires_tshark
def test_analyze_reports_signature_matches(cli_runner, tmp_path, cache_dir) -> None:
    rules = tmp_path / "pf.rules"
    rules.write_text(RULES)
    out = tmp_path / "r"
    args = ["analyze", str(fixture("http_basic.pcap")), "-o", str(out), "-q", "--no-handoff", "--signatures", str(rules)]
    assert cli_runner.invoke(app, args).exit_code == 0
    report = json.loads((out / "report.json").read_text())
    hits = [f for f in report["findings"] if f["code"] == "SIGNATURE_MATCH"]
    # 9100002 is silenced: the pass rule 9100005 matched the response packet first
    assert [h["title"] for h in hits] == ["Signature 9100001: PF password in form"]
    cred = next(h for h in hits if "9100001" in h["title"])
    assert cred["severity"] == "high" and cred["evidence"][0]["frame"] == 3 and "credential-theft" in cred["tags"]
    notes = "\n".join(report["notes"])
    assert "[signatures] 5 rule(s) loaded, 1 match(es)" in notes and "http_uri" in notes
    # without --signatures there is no finding
    plain = tmp_path / "p"
    assert cli_runner.invoke(app, ["analyze", str(fixture("http_basic.pcap")), "-o", str(plain), "-q", "--no-handoff"]).exit_code == 0
    assert "SIGNATURE_MATCH" not in (plain / "report.json").read_text()


@requires_tshark
def test_a_pattern_split_across_tcp_segments_still_matches(cli_runner, tmp_path, cache_dir) -> None:
    from parity_fixtures import MAC_A, Tcp, Wire

    w = Wire()
    t = Tcp(w, "10.0.0.5", "10.0.0.6", 40000, 80).open()
    t.send(True, b"GET /ad")
    t.send(True, b"min/panel HTTP/1.1\r\nHost: x\r\n\r\n")
    pcap = tmp_path / "split.pcap"
    pcap.write_bytes(w.write())
    assert MAC_A
    rules = tmp_path / "s.rules"
    rules.write_text('alert tcp any any -> any 80 (msg:"admin panel"; content:"/admin/panel"; sid:7;)\n')
    out = tmp_path / "r"
    assert cli_runner.invoke(app, ["analyze", str(pcap), "-o", str(out), "-q", "--no-handoff", "--signatures", str(rules)]).exit_code == 0
    hit = next(f for f in json.loads((out / "report.json").read_text())["findings"] if f["code"] == "SIGNATURE_MATCH")
    assert hit["evidence"][0]["frame"] == 6  # the second data segment completes the pattern
