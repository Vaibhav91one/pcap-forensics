"""Stream follow and the stream list (issue #197)."""

from __future__ import annotations

from conftest import FIXTURES, fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.follow import parse_follow


def test_parse_follow_splits_directions_on_the_leading_tab() -> None:
    text = (
        "====\nFollow: tcp,raw\nFilter: tcp.stream eq 0\nNode 0: 1.1.1.1:5\nNode 1: 2.2.2.2:80\n"
        "474554\n\t485454\n6162\n====\n"
    )
    s = parse_follow(text, "tcp", 0)
    assert (s.node0, s.node1) == ("1.1.1.1:5", "2.2.2.2:80")
    assert [(g.to_client, g.data) for g in s.segments] == [(False, b"GET"), (True, b"HTT"), (False, b"ab")]
    assert s.payload("client") == b"GETab" and s.payload("server") == b"HTT"


@requires_tshark
def test_follow_tcp_shows_both_directions(cli_runner) -> None:
    out = cli_runner.invoke(app, ["follow", str(fixture("http_basic.pcap")), "tcp", "0"]).output
    assert "--- client -> server (213 bytes)" in out and "POST /login HTTP/1.1" in out
    assert "--- server -> client (101 bytes)" in out and "HTTP/1.1 200 OK" in out


@requires_tshark
def test_follow_udp_hex_and_out_file(cli_runner, tmp_path) -> None:
    pcap = str(fixture("dns_tunnel.pcap"))
    assert "00000000  20 00 01 00" in cli_runner.invoke(app, ["follow", pcap, "udp", "0", "--as", "hex"]).output
    dest = tmp_path / "p.bin"
    assert cli_runner.invoke(app, ["follow", pcap, "udp", "0", "-o", str(dest), "--direction", "client"]).exit_code == 0
    assert dest.read_bytes()[:4] == bytes.fromhex("20000100") and len(dest.read_bytes()) == 68


@requires_tshark
def test_follow_tls_and_http_need_the_key(cli_runner) -> None:
    pcap = str(FIXTURES / "rsa_kx.pcap")
    plain = cli_runner.invoke(app, ["follow", pcap, "tls", "0"]).output
    assert "no stream 0 for tls" in plain and "--tls-key" in plain and "GET /" not in plain
    keyed = cli_runner.invoke(app, ["follow", pcap, "http", "0", "--tls-key", str(FIXTURES / "rsa_kx.key")]).output
    assert "GET / HTTP/1.1" in keyed


@requires_tshark
def test_unknown_stream_and_protocol_exit_2(cli_runner) -> None:
    pcap = str(fixture("http_basic.pcap"))
    assert cli_runner.invoke(app, ["follow", pcap, "tcp", "7"]).exit_code == 2
    assert cli_runner.invoke(app, ["follow", pcap, "gopher", "0"]).exit_code == 2


@requires_tshark
def test_streams_lists_tcp_and_udp_numbers(cli_runner) -> None:
    out = cli_runner.invoke(app, ["streams", str(fixture("dns_tunnel.pcap")), "--proto", "udp"]).output
    assert "10.0.0.10:40000" in out and "10.0.0.20:53" in out and "tcp" not in out.replace("proto", "")
