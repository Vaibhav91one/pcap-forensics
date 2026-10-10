"""Suricata EVE JSON events (issue #200)."""

from __future__ import annotations

import json

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.eve import signature_id


def _events(cli_runner, name: str, *extra: str) -> list[dict]:
    result = cli_runner.invoke(app, ["eve", str(fixture(name)), *extra])
    assert result.exit_code == 0, result.output
    return [json.loads(line) for line in result.output.splitlines()]


def test_signature_id_is_stable_and_in_the_private_range() -> None:
    assert signature_id("TLS_CIPHER_WEAK") == signature_id("TLS_CIPHER_WEAK") == 9000018
    assert 9_000_000 <= signature_id("anything") < 10_000_000


@requires_tshark
def test_every_event_has_the_eve_envelope_and_is_time_ordered(cli_runner) -> None:
    events = _events(cli_runner, "logs_mix.pcap")
    assert {e["event_type"] for e in events} == {"flow", "alert", "fileinfo"}  # fileinfo: the SMTP message
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)
    for e in (e for e in events if e["event_type"] != "fileinfo"):  # SMTP/POP3/FTP/TFTP files carry no flow yet
        assert e["timestamp"].endswith("+0000") and isinstance(e["flow_id"], int)
        assert {"src_ip", "src_port", "dest_ip", "dest_port", "proto"} <= set(e)
    smtp = next(e for e in events if e["event_type"] == "flow" and e["dest_port"] == 25)
    assert smtp["app_proto"] == "smtp" and smtp["proto"] == "TCP" and smtp["flow"]["pkts_toserver"] == 17
    alert = next(e for e in events if e["event_type"] == "alert")
    assert alert["alert"]["category"] == "CLEARTEXT_SERVICE" and alert["alert"]["severity"] == 2
    assert alert["flow_id"] == smtp["flow_id"]


@requires_tshark
def test_tls_dns_http_and_type_filter(cli_runner) -> None:
    tls = _events(cli_runner, "weak_tls.pcap", "--types", "tls")
    assert len(tls) == 1 and tls[0]["tls"]["sni"] == "weak.example" and tls[0]["tls"]["ja3"]["hash"]
    assert tls[0]["tls"]["subject"] == "CN=weak.example"
    dns = _events(cli_runner, "dns_tunnel.pcap", "--types", "dns")
    assert dns[0]["dns"] == {"type": "query", "id": 0, "rrname": dns[0]["dns"]["rrname"], "rrtype": "TXT"}
    http = _events(cli_runner, "http_basic.pcap", "--types", "http")
    assert http[0]["http"]["http_method"] == "POST" and http[0]["http"]["url"] == "/login"
    files = _events(cli_runner, "http_cleartext.pcap", "--types", "fileinfo")
    assert files and files[0]["event_type"] == "fileinfo"


@requires_tshark
def test_bad_type_exits_2_and_out_file(cli_runner, tmp_path) -> None:
    pcap = str(fixture("http_basic.pcap"))
    assert cli_runner.invoke(app, ["eve", pcap, "--types", "bogus"]).exit_code == 2
    dest = tmp_path / "eve.json"
    assert cli_runner.invoke(app, ["eve", pcap, "-o", str(dest)]).exit_code == 0
    assert all(json.loads(line)["event_type"] for line in dest.read_text().splitlines())
