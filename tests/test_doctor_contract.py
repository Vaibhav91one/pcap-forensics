"""doctor/1 conformance (docs/doctor-contract.md sections 1-4, 8, 9)."""

from __future__ import annotations

import json
import re

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli import app
from test_capture_text_sanitised import _hostile_capture

SEVERITIES = {"critical", "high", "medium", "low", "info"}
TOP = {"schema", "tool", "version", "exit_code", "score", "findings", "data"}
KINDS = {"file", "flow", "frame", "image", "card-path", "device", "service", "none"}


def _run(cli_runner, tmp_path, name, *extra):
    result = cli_runner.invoke(
        app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "-o", str(tmp_path / name), "--json", "--fail-on", "high", *extra]
    )
    return result, json.loads(result.output)


@requires_tshark
def test_the_json_envelope_conforms(cli_runner, tmp_path, cache_dir) -> None:
    result, env = _run(cli_runner, tmp_path, "a")
    assert set(env) == TOP and env["schema"] == "doctor/1" and env["tool"] == "pcap-doctor"
    assert env["exit_code"] == result.exit_code == 1
    assert set(env["score"]) == {"value", "label", "model", "coverage_gaps"}
    assert env["findings"]
    for f in env["findings"]:
        assert {"id", "fingerprint", "severity", "category", "message", "location", "remedy"} <= set(f)
        assert f["severity"] in SEVERITIES and f.get("confidence", "high") in {"certain", "high", "medium", "low"}
        assert re.fullmatch(r"[0-9a-f]{16}", f["fingerprint"])
        assert f["location"]["kind"] in KINDS and isinstance(f["message"], str)
        assert all(set(e) == {"ref", "value"} for e in f["evidence"])
    order = [(("critical", "high", "medium", "low", "info").index(f["severity"]), f["id"], f["fingerprint"]) for f in env["findings"]]
    assert order == sorted(order)
    again = _run(cli_runner, tmp_path, "b")[1]
    assert {k: v for k, v in env.items() if k != "data"} == {k: v for k, v in again.items() if k != "data"}


@requires_tshark
def test_a_new_finding_under_a_baseline_exits_3(cli_runner, tmp_path, cache_dir) -> None:
    _, env = _run(cli_runner, tmp_path, "a")
    env["findings"].pop(0)  # the worst one, so it is at the --fail-on threshold
    base = tmp_path / "base.json"
    base.write_text(json.dumps(env))
    result, out = _run(cli_runner, tmp_path, "c", "--baseline", str(base))
    assert result.exit_code == out["exit_code"] == 3
    assert out["baseline"]["new"] == 1 and {f["baseline_state"] for f in out["findings"]} == {"new", "unchanged"}
    same, _ = _run(cli_runner, tmp_path, "d", "--baseline", str(tmp_path / "a" / "report.json"))
    assert same.exit_code == 0


@requires_tshark
def test_an_escape_sequence_in_the_capture_never_reaches_the_human_output(cli_runner, tmp_path, cache_dir) -> None:
    capture = _hostile_capture(tmp_path)
    summary = cli_runner.invoke(app, ["analyze", str(capture), "-o", str(tmp_path / "o"), "--no-handoff", "-v"])
    assert "\x1b" not in summary.output and "HTTP_CLEARTEXT" in summary.output
    report = json.loads((tmp_path / "o" / "report.json").read_text())
    finding_id = next(f["id"] for f in report["findings"] if f["code"] == "HTTP_CLEARTEXT")
    why = cli_runner.invoke(app, ["why", finding_id, "--report", str(tmp_path / "o" / "report.json")])
    assert "\x1b" not in why.output
