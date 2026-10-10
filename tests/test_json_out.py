"""`--json` prints only the envelope; `--json-out` writes it next to the normal output (issue #54)."""

from __future__ import annotations

import json

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.models import SCHEMA_VERSION, CaptureInfo, Finding, Report, Stats
from pcap_doctor.output import json_envelope


def _report() -> Report:
    finding = Finding.make(
        detector="d4.dns_quic_ssh", code="DNS_CLEARTEXT", title="t", severity="medium", confidence="high",
        category="dns", summary="", scope="s",
    )
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=[finding])


def test_envelope_shape() -> None:
    envelope = json_envelope(_report())
    assert envelope["tool"] == "pcap-doctor"
    assert envelope["score"] == {"value": 95, "label": "good", "model": "pcap/1", "coverage_gaps": 0}
    assert envelope["data"]["categories"] == {"DNS": 1}
    assert envelope["data"]["schema_version"] == SCHEMA_VERSION
    assert "findings" not in envelope["data"]
    json.dumps(envelope)


@requires_tshark
def test_json_flag_prints_only_json(cli_runner, tmp_path, cache_dir) -> None:
    result = cli_runner.invoke(
        app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "-o", str(tmp_path / "r"), "--json", "--fail-on", "high"]
    )
    assert result.exit_code == 1
    envelope = json.loads(result.output)
    assert envelope["data"]["schema_version"] == SCHEMA_VERSION
    assert envelope["score"]["value"] < 100


@requires_tshark
def test_json_out_writes_the_envelope_and_keeps_the_summary(cli_runner, tmp_path, cache_dir) -> None:
    target = tmp_path / "envelope.json"
    result = cli_runner.invoke(
        app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "-o", str(tmp_path / "r"), "--json-out", str(target)]
    )
    assert result.exit_code == 0
    assert "Score " in result.output
    assert json.loads(target.read_text())["tool"] == "pcap-doctor"
