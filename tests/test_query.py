"""The query language over flows, protocol rows and findings (issue #198)."""

from __future__ import annotations

import json

import pytest

from conftest import fixture, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.query import Query, QueryError, filter_rows

ROWS = [
    {"id": 1, "src": "10.1.2.3", "port": 443, "app": "tls", "bytes": 9000, "tags": ["a", "b"], "meta": {"k": "v"}, "up": True},
    {"id": 2, "src": "192.168.0.9", "port": 80, "app": "http", "bytes": 100, "tags": [], "meta": {"k": "w"}, "up": False},
    {"id": 3, "src": "8.8.8.8", "port": 53, "app": "dns", "bytes": 50, "tags": ["b"], "meta": {"k": "v"}, "up": False},
]


def ids(text: str) -> list[int]:
    return [r["id"] for r in filter_rows(ROWS, text)]


def test_comparisons_and_logic() -> None:
    assert ids("bytes > 60") == [1, 2]
    assert ids("app == tls or app == 'dns'") == [1, 3]
    assert ids("bytes >= 100 and not up") == [2]
    assert ids("app == tls || app == http && bytes < 1000") == [1, 2]  # && binds tighter than ||
    assert ids("(app == tls or app == http) and port != 80") == [1]


def test_sets_contains_regex_and_bare_fields() -> None:
    assert ids("port in {80 53}") == [2, 3]
    assert ids("port not in [80, 53]") == [1]
    assert ids("src contains 192.168") == [2]
    assert ids('app matches "^h"') == [2]
    assert ids("app ~ 't.s'") == [1]
    assert ids("up") == [1]
    assert ids("meta.k == v") == [1, 3]


def test_lists_match_any_element_and_cidr_is_membership() -> None:
    assert ids("tags == a") == [1]
    assert ids("tags contains b") == [1, 3]
    assert ids("src == 10.0.0.0/8") == [1]
    assert ids("src != 10.0.0.0/8") == [2, 3]


@pytest.mark.parametrize(
    "bad",
    ["", "port ==", "nofield == 1", "(port == 1", "port in 5", "app matches '['", "port == 1 extra", "@@"],
)
def test_errors_are_query_errors_not_tracebacks(bad: str) -> None:
    with pytest.raises(QueryError):
        filter_rows(ROWS, bad)


def test_unknown_field_error_lists_the_known_ones() -> None:
    with pytest.raises(QueryError, match=r"fields: .*bytes"):
        Query("nope == 1", {"bytes", "port"})


def test_input_is_never_evaluated() -> None:
    with pytest.raises(QueryError):
        filter_rows(ROWS, "__import__('os').system('true')")


@requires_tshark
def test_cli_query_on_flows_and_findings(cli_runner) -> None:
    pcap = str(fixture("dns_tunnel.pcap"))
    rows = json.loads(cli_runner.invoke(app, ["query", pcap, "proto == tcp", "--json"]).output)
    assert [r["port_a"] for r in rows] == [43000]
    found = json.loads(cli_runner.invoke(app, ["query", pcap, "code == DNS_TUNNEL_SHAPE", "-s", "findings", "--json"]).output)
    assert found and found[0]["code"] == "DNS_TUNNEL_SHAPE"
    http = json.loads(cli_runner.invoke(app, ["query", str(fixture("http_basic.pcap")), "method == POST", "-s", "http", "--json"]).output)
    assert [r["uri"] for r in http] == ["/login"]


@requires_tshark
def test_cli_rejects_bad_expressions_with_exit_2(cli_runner) -> None:
    pcap = str(fixture("dns_tunnel.pcap"))
    assert cli_runner.invoke(app, ["query", pcap, "bogus == 1"]).exit_code == 2
    assert cli_runner.invoke(app, ["query", pcap, "bytes > 1", "-s", "nope"]).exit_code == 2


@requires_tshark
def test_flows_filter(cli_runner) -> None:
    out = cli_runner.invoke(app, ["flows", str(fixture("dns_tunnel.pcap")), "-f", "proto == tcp"]).output
    assert "1 flows in dns_tunnel.pcap" in out and "43000" in out
