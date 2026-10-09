"""`--baseline` reports and gates only findings that are new since an earlier report (issue #55)."""

from __future__ import annotations

import json
from json import dumps as json_dumps

from conftest import FIXTURES, requires_tshark
from pcapforensics.baseline import Baseline, finding_fingerprint, load_baseline, new_since, version_drift
from pcapforensics.cli import app
from pcapforensics.models import CaptureInfo, Finding, Report, Stats
from pcapforensics.output import json_envelope


def _finding(code: str) -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=code, severity="high", confidence="high",
        category="crypto", summary="", scope=code,
    )


def _report(codes: list[str], versions: dict[str, str] | None = None) -> Report:
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(
        generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[],
        findings=[_finding(c) for c in codes], detector_versions=versions or {},
    )


def _base(report: Report) -> Baseline:
    return Baseline(frozenset(map(finding_fingerprint, report.findings)), report.detector_versions)


def test_new_since_matches_by_fingerprint() -> None:
    old, now = _report(["A", "B"]), _report(["B", "C"])
    assert [f.code for f in new_since(_base(old), now.findings)] == ["C"]


def test_version_drift_names_changed_detectors() -> None:
    old = _report([], {"d1.tls_cipher": "1", "d2.x": "1"})
    assert version_drift(_base(old), _report([], {"d1.tls_cipher": "2", "d2.x": "1", "d9.new": "1"})) == ["d1.tls_cipher"]


def test_load_baseline_accepts_report_and_doctor_envelope(tmp_path) -> None:
    report = _report(["A"])
    (tmp_path / "r.json").write_text(report.model_dump_json())
    (tmp_path / "e.json").write_text(json_dumps(json_envelope(report)))
    expected = {finding_fingerprint(report.findings[0])}
    assert load_baseline(tmp_path / "r.json").fingerprints == expected
    assert load_baseline(tmp_path / "e.json").fingerprints == expected


def test_bad_baseline_exits_2_before_tshark(cli_runner, tmp_path, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("analyze must not run")

    monkeypatch.setattr("pcapforensics.cli.analyze.analyze", boom)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "--baseline", str(bad)])
    assert result.exit_code == 2


@requires_tshark
def test_capture_against_its_own_report_has_nothing_new(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(FIXTURES / "weak_tls.pcap")
    assert cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "a"), "-q"]).exit_code == 0
    base = tmp_path / "a" / "report.json"
    result = cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "b"), "--baseline", str(base), "--fail-on", "low"])
    assert result.exit_code == 0
    assert "0 new finding(s) since the baseline" in result.output
    assert json.loads((tmp_path / "b" / "report.json").read_text())["findings"]  # artifacts stay complete


@requires_tshark
def test_removed_baseline_finding_is_exactly_the_new_one(cli_runner, tmp_path, cache_dir) -> None:
    pcap = str(FIXTURES / "weak_tls.pcap")
    first = cli_runner.invoke(app, ["analyze", pcap, "-o", str(tmp_path / "a"), "-q", "--json"])
    base = tmp_path / "base.json"
    data = json.loads(first.output)
    dropped = data["findings"].pop()
    base.write_text(json.dumps(data))
    result = cli_runner.invoke(
        app, ["analyze", pcap, "-o", str(tmp_path / "b"), "--baseline", str(base), "--json", "--fail-on", "low"]
    )
    envelope = json.loads(result.output)
    assert [f["fingerprint"] for f in envelope["findings"] if f["baseline_state"] == "new"] == [dropped["fingerprint"]]
    assert envelope["baseline"] == {"new": 1, "unchanged": len(data["findings"]), "fixed": 0}
    assert result.exit_code == envelope["exit_code"] == 3  # a new finding at the threshold


def _flow_finding(key: str, code: str = "TLS_CIPHER_WEAK") -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=f"TLS_RSA_WITH_AES_128_CBC_SHA negotiated on {key}",
        severity="high", confidence="high", category="crypto", summary="", scope=key, flow_key=key,
    )


def test_recapture_with_new_client_ports_has_nothing_new() -> None:
    # #126: the same device captured twice: only the client's ephemeral port differs, so every id differs
    old = _report([])
    old.findings[:] = [_flow_finding("tcp:10.9.0.1:38288<->10.9.0.2:443"), _flow_finding("udp:127.0.0.1:4433<->127.0.0.1:54273")]
    now = [_flow_finding("tcp:10.9.0.1:51122<->10.9.0.2:443"), _flow_finding("udp:127.0.0.1:4433<->127.0.0.1:60001")]
    assert [f.id for f in now] != [f.id for f in old.findings]
    assert new_since(_base(old), now) == []


def test_recapture_still_reports_a_new_server_or_code() -> None:
    old = _report([])
    old.findings[:] = [_flow_finding("tcp:10.9.0.1:38288<->10.9.0.2:443")]
    other_port = _flow_finding("tcp:10.9.0.1:38288<->10.9.0.2:8443")
    other_host = _flow_finding("tcp:10.9.0.1:38288<->10.9.0.3:443")
    other_code = _flow_finding("tcp:10.9.0.1:51122<->10.9.0.2:443", code="TLS_VERSION_DEPRECATED")
    ipv6 = _flow_finding("tcp:2001:db8:1::1:57098<->2606:4700:10::6816:826:443")
    assert new_since(_base(old), [other_port, other_host, other_code, ipv6]) == [other_port, other_host, other_code, ipv6]


def test_same_title_from_another_host_is_new() -> None:
    # #126 review: a title that names no host must not hide the same finding on another flow
    def offers(key: str) -> Finding:
        return Finding.make(
            detector="d1.tls_cipher", code="TLS_OFFERS_WEAK_CIPHERS", title="Client offers 4 prohibited/deprecated suites",
            severity="medium", confidence="high", category="crypto", summary="", scope=key, flow_key=key,
        )

    old = _report([])
    old.findings[:] = [offers("tcp:10.9.0.1:38288<->10.9.0.2:443")]
    same_device, other_host = offers("tcp:10.9.0.1:51122<->10.9.0.2:443"), offers("tcp:10.9.0.7:51122<->10.9.0.2:443")
    assert new_since(_base(old), [same_device, other_host]) == [other_host]


def test_fingerprint_ignores_counts_but_not_the_server() -> None:
    def offers(n: int, key: str) -> Finding:
        return Finding.make(
            detector="d1.tls_cipher", code="TLS_OFFERS_WEAK_CIPHERS", title=f"Client offers {n} prohibited suites",
            severity="medium", confidence="high", category="crypto", summary="", scope=key, flow_key=key,
        )

    key = "tcp:10.9.0.1:38288<->10.9.0.2:443"
    assert finding_fingerprint(offers(4, key)) == finding_fingerprint(offers(7, key))
    assert finding_fingerprint(offers(4, key)) != finding_fingerprint(offers(4, "tcp:10.9.0.1:38288<->10.9.0.2:8443"))
