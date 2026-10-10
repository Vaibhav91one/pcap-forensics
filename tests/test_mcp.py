"""`pcap-doctor mcp`: stdio JSON-RPC server whose `analyze` returns the CLI envelope byte for byte (#186)."""

from __future__ import annotations

import json
import subprocess
import sys

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli.mcp import BY_NAME, TOOLS, argv_of


def _session(*messages: dict) -> list[dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "pcap_doctor.cli", "mcp"], input="\n".join(map(json.dumps, messages)) + "\n",
        capture_output=True, text=True, timeout=300, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines()]


def test_handshake_and_tool_list() -> None:
    init, listing, unknown = _session(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "nope"},
    )
    assert init["result"]["serverInfo"]["name"] == "pcap-doctor" and "tools" in init["result"]["capabilities"]
    assert len(listing["result"]["tools"]) >= 10
    assert {"analyze", "why", "rules_list", "keys_scan"} <= {t["name"] for t in listing["result"]["tools"]}
    assert unknown["error"]["code"] == -32601


def test_argv_passthrough_and_validation() -> None:
    argv = argv_of(BY_NAME["analyze"], {"path": "-x.pcap", "baseline": "b.json", "fail_on": "high", "sarif": "s.sarif", "only": ["a", "b"]})
    assert argv[:3] == ["analyze", "--json", "--no-handoff"]
    assert argv[3:] == ["--only", "a", "--only", "b", "--fail-on", "high", "--baseline", "b.json", "--sarif", "s.sarif", "--", "-x.pcap"]
    for bad in ({}, {"path": "x", "nope": 1}):
        try:
            argv_of(BY_NAME["analyze"], bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    assert len(TOOLS) >= 10


@requires_tshark
def test_analyze_is_byte_identical_to_the_cli(tmp_path, cache_dir) -> None:
    pcap = str(FIXTURES / "weak_tls.pcap")
    cli = subprocess.run(
        [sys.executable, "-m", "pcap_doctor.cli", "analyze", pcap, "--json", "--no-handoff", "--fail-on", "high",
         "-o", str(tmp_path / "r")],
        capture_output=True, text=True, timeout=300, check=False,
    )
    (reply,) = _session({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "analyze", "arguments": {"path": pcap, "fail_on": "high", "out": str(tmp_path / "r")}},
    })
    result = reply["result"]
    assert cli.returncode == 1 and result["isError"] is False
    mine, theirs = json.loads(result["content"][0]["text"]), json.loads(cli.stdout)
    assert mine.pop("data")["capture"] == theirs.pop("data")["capture"] and mine == theirs  # data holds generated_at
    assert result["content"][0]["text"].count("\n") == cli.stdout.count("\n")  # same indent=2 rendering
    assert json.loads(cli.stdout)["exit_code"] == 1


def test_a_failing_cli_call_is_an_error_result() -> None:
    (reply,) = _session({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rules_explain", "arguments": {"code": "NOPE_NOPE"}}})
    assert reply["result"]["isError"] is True
