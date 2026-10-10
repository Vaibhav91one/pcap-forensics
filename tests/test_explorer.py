"""Per-packet explorer: list, dissection tree, hex view (issue #196)."""

from __future__ import annotations

import json

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app


@requires_tshark
def test_packet_list_with_a_display_filter(cli_runner) -> None:
    result = cli_runner.invoke(app, ["packets", str(fixture("http_basic.pcap")), "-Y", "http.request", "--json"])
    assert result.exit_code == 0
    rows = json.loads(result.output)
    assert [r["frame"] for r in rows] == [3]
    assert rows[0]["source"] == "10.0.0.10" and rows[0]["protocol"] == "HTTP" and rows[0]["info"].startswith("POST /login")


@requires_tshark
def test_packet_shows_the_tree_and_the_hex_view(cli_runner) -> None:
    result = cli_runner.invoke(app, ["packet", str(fixture("http_basic.pcap")), "3"])
    assert result.exit_code == 0
    assert "Hypertext Transfer Protocol" in result.output and "Request URI: /login" in result.output
    assert "\n    Encapsulation type" in result.output  # the tree keeps its indentation
    first_hex = next(line for line in result.output.splitlines() if line.startswith("0000  "))
    assert first_hex.startswith("0000  00 11 22 33 44 55 66 77 88 99 aa bb 08 00 45 00")
    assert result.output.count("0000  ") == 1  # one hex block only


@requires_tshark
def test_packet_json_and_no_hex(cli_runner) -> None:
    pcap = str(fixture("http_basic.pcap"))
    tree = json.loads(cli_runner.invoke(app, ["packet", pcap, "3", "--json"]).output)
    assert tree["_source"]["layers"]["http"]["http.host"] == "portal.example"
    assert "0000  " not in cli_runner.invoke(app, ["packet", pcap, "3", "--no-hex"]).output


@requires_tshark
def test_bad_frame_and_bad_filter_exit_2_without_the_corrupt_capture_hint(cli_runner) -> None:
    pcap = str(fixture("http_basic.pcap"))
    missing = cli_runner.invoke(app, ["packet", pcap, "999"])
    assert missing.exit_code == 2 and "no frame 999" in missing.output and "corrupt" not in missing.output
    bad = cli_runner.invoke(app, ["packets", pcap, "-Y", "tcp.port =="])
    assert bad.exit_code == 2 and "corrupt" not in bad.output
