"""End-to-end detector tests against the synthetic fixtures.

Each fixture exists to prove one thing. The assertions are on *finding codes*,
not on prose, so a rewording never breaks the suite and a regression in
detection always does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import codes, fixture, load_json, requires_tshark

pytestmark = requires_tshark


# ---------------------------------------------------------------- D1: crypto
def test_weak_tls_fixture_raises_every_crypto_finding(analyze_capture) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    found = codes(result)
    assert "TLS_VERSION_DEPRECATED" in found
    assert "TLS_CIPHER_WEAK" in found
    assert "TLS_NO_FORWARD_SECRECY" in found
    assert "TLS_SELF_SIGNED_CHAIN" in found
    deprecated = [f for f in result.report.findings if f.code == "TLS_VERSION_DEPRECATED"]
    assert deprecated and deprecated[0].severity == "high"


def test_weak_tls_fixture_reports_the_negotiated_values(analyze_capture) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    (session,) = result.index.tls.values()
    assert session.negotiated_version == "TLS 1.0"
    assert session.chosen_cipher == 0x002F  # TLS_RSA_WITH_AES_128_CBC_SHA
    assert session.sni == "weak.example"
    assert session.complete is True
    assert session.offered_ciphers  # every suite in the ClientHello, not just the first
    assert session.forward_secrecy is False
    assert len(session.certs) == 1
    cert = session.certs[0]
    assert cert.public_key_bits == 2048
    assert cert.subject and cert.issuer
    assert cert.self_signed_suspected is True
    assert cert.name_source == "openssl"


def test_offered_but_unused_weak_suites_are_reported(analyze_capture) -> None:
    """Client offers legacy CBC; server picks ECDHE-AEAD. Session is fine, list is not."""
    result = analyze_capture(fixture("mixed_ciphers.pcap"))
    found = codes(result)
    assert "TLS_OFFERS_WEAK_CIPHERS" in found
    assert "TLS_CIPHER_WEAK" not in found
    (session,) = result.index.tls.values()
    assert session.chosen_cipher == 0xC02F  # ECDHE_RSA_AES_128_GCM_SHA256
    assert session.forward_secrecy is True
    assert len(session.offered_ciphers) >= 4


def test_no_forward_secrecy_fixture(analyze_capture) -> None:
    result = analyze_capture(fixture("no_pfs_tls12.pcap"))
    found = codes(result)
    assert {"TLS_CIPHER_WEAK", "TLS_NO_FORWARD_SECRECY"} <= found
    (session,) = result.index.tls.values()
    assert session.negotiated_version == "TLS 1.2"
    assert session.chosen_cipher == 0x002F
    assert session.forward_secrecy is False
    assert "static" in (session.forward_secrecy_reason or "")


def test_weak_tls_findings_carry_frame_numbered_evidence(analyze_capture) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    for finding in result.report.findings:
        assert finding.evidence, f"{finding.code} has no evidence"
        for item in finding.evidence:
            assert item.frame > 0
            assert item.field
            assert item.value


def test_strong_tls13_fixture_is_clean(analyze_capture) -> None:
    """The counter-example: a modern handshake must produce zero crypto findings."""
    result = analyze_capture(fixture("strong_tls13.pcap"))
    (session,) = result.index.tls.values()
    assert session.negotiated_version == "TLS 1.3"
    assert session.chosen_cipher in (0x1301, 0x1302, 0x1303)
    assert session.forward_secrecy is True
    assert not (
        codes(result)
        & {
            "TLS_VERSION_DEPRECATED",
            "TLS_CIPHER_WEAK",
            "TLS_NO_FORWARD_SECRECY",
            "TLS_OFFERS_WEAK_CIPHERS",
            "TLS_SELF_SIGNED_CHAIN",
        }
    )


# ------------------------------------------------------------- D2: cleartext
def test_http_basic_auth_fixture(analyze_capture) -> None:
    result = analyze_capture(fixture("http_basic.pcap"))
    found = codes(result)
    assert "HTTP_CLEARTEXT_AUTH" in found
    assert "HTTP_COOKIE_NO_SECURE" in found
    assert "HTTP_BASIC_AUTH" not in found  # that code is for the same auth *inside* TLS


def test_reports_never_contain_the_credential(analyze_capture, tmp_path: Path) -> None:
    """A report is meant to be pasted into a ticket: no secrets may survive."""
    result = analyze_capture(fixture("http_basic.pcap"))
    joined = "".join(path.read_text() for path in result.artifacts)
    assert "YWRtaW46aHVudGVyMg==" not in joined, "raw Basic credential leaked into a report"
    assert "hunter2" not in joined, "decoded credential leaked into a report"
    assert "redacted" in joined, "the redaction notice is missing"


def test_service_credentials_are_redacted(analyze_capture) -> None:
    """SNMP community strings must never reach a report (issue #1)."""
    result = analyze_capture(fixture("snmp_creds.pcap"))
    assert {"CLEARTEXT_SERVICE", "CLEARTEXT_CREDENTIAL"} <= codes(result)
    joined = "".join(path.read_text() for path in result.artifacts)
    assert "pf-s3cr3t-7f" not in joined, "raw SNMP community leaked into a report"
    assert "redacted" in joined, "the redaction notice is missing"


def test_syn_scan_shape(analyze_capture) -> None:
    result = analyze_capture(fixture("syn_scan.pcap"))
    assert "SYN_SCAN_SHAPE" in codes(result)
    (finding,) = [f for f in result.report.findings if f.code == "SYN_SCAN_SHAPE"]
    assert finding.subjects == ["10.0.0.10"]
    assert result.report.stats.flows == 39


# ---------------------------------------------------------------- D3: voice
def test_sip_rtp_fixture(analyze_capture) -> None:
    result = analyze_capture(fixture("sip_rtp.pcap"))
    found = codes(result)
    assert "SIP_CLEARTEXT_SIGNALLING" in found
    assert "SDP_NO_CRYPTO_ATTR" in found
    assert "RTP_MEDIA_UNPROTECTED" in found
    assert result.report.stats.rtp_streams == 1
    assert result.report.stats.sip_messages >= 2


def test_sip_digest_credentials_are_not_echoed(analyze_capture) -> None:
    result = analyze_capture(fixture("sip_rtp.pcap"))
    for path in result.artifacts:
        assert "deadbeef" not in path.read_text(), f"SIP digest response leaked into {path.name}"


# ------------------------------------------------------------------ D4: dns
def test_dns_tunnel_fixture(analyze_capture) -> None:
    result = analyze_capture(fixture("dns_tunnel.pcap"))
    assert "DNS_TUNNEL_SHAPE" in codes(result)
    (finding,) = [f for f in result.report.findings if f.code == "DNS_TUNNEL_SHAPE"]
    assert finding.severity in {"medium", "high"}
    assert "10.0.0.10" in finding.subjects


def test_dns_cleartext_is_reported(analyze_capture) -> None:
    result = analyze_capture(fixture("dns_tunnel.pcap"))
    assert "DNS_CLEARTEXT" in codes(result)


# ------------------------------------------------------------------ plumbing
def test_every_artifact_is_written(analyze_capture) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    names = {p.name for p in result.artifacts}
    assert names == {"index.md", "01-flows.md", "02-ciphers.md", "03-findings.md", "04-diagrams.md", "report.json"}
    for path in result.artifacts:
        assert path.exists() and path.stat().st_size > 0


def test_report_json_round_trips(analyze_capture) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    payload = load_json(result.outdir / "report.json")
    assert payload["schema_version"] == result.report.schema_version
    assert payload["capture"]["sha256"] == result.report.capture.sha256
    assert len(payload["findings"]) == len(result.report.findings)
    json.dumps(payload)  # must be serialisable as-is


def test_finding_ids_are_stable_across_runs(analyze_capture) -> None:
    from pcapforensics.pipeline import analyze

    pcap = fixture("weak_tls.pcap")
    first = {f.id for f in analyze(pcap, analyze_capture(pcap).outdir / "a").report.findings}
    second = {f.id for f in analyze(pcap, analyze_capture(pcap).outdir / "b").report.findings}
    assert first == second


def test_mermaid_blocks_are_balanced(analyze_capture) -> None:
    result = analyze_capture(fixture("sip_rtp.pcap"))
    text = (result.outdir / "04-diagrams.md").read_text()
    assert text.count("```mermaid") == text.count("\n```") - text.count("\n```mermaid")
    for block in text.split("```mermaid")[1:]:
        body = block.split("```")[0]
        assert body.strip(), "empty mermaid block"


def test_index_artifact_is_the_navigation_page(analyze_capture) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    index = (result.outdir / "index.md").read_text()
    assert "Capture report" in index
    for artifact in ("01-flows.md", "02-ciphers.md", "03-findings.md", "04-diagrams.md", "report.json"):
        assert artifact in index


def test_min_severity_filter(analyze_capture) -> None:
    from pcapforensics.pipeline import analyze

    pcap = fixture("weak_tls.pcap")
    everything = analyze(pcap, analyze_capture(pcap).outdir / "all")
    critical_only = analyze(
        pcap, analyze_capture(pcap).outdir / "crit", min_severity="critical"
    )
    assert len(critical_only.report.findings) <= len(everything.report.findings)
    assert all(f.severity in {"critical"} for f in critical_only.report.findings)


def test_detector_failure_is_contained(analyze_capture, monkeypatch) -> None:
    """A broken detector must not take the whole run down."""
    from pcapforensics.pipeline import analyze
    from pcapforensics.registry import all_detectors

    original = all_detectors()

    class Exploding:
        name = "d0.exploding"
        version = "1"
        enabled = True
        title = "explodes"

        def detect(self, index):
            raise RuntimeError("boom")

    monkeypatch.setattr("pcapforensics.pipeline.enabled_detectors", lambda include=(): [*original, Exploding()])
    pcap = fixture("weak_tls.pcap")
    result = analyze(pcap, analyze_capture(pcap).outdir / "boom")
    assert any("exploding" in note for note in result.report.notes)
    assert "TLS_CIPHER_WEAK" in codes(result)


def test_pipeline_never_leaks_the_auth_header_value(analyze_capture) -> None:
    result = analyze_capture(fixture("http_basic.pcap"))
    for exchange in result.index.http:
        if exchange.auth_value_preview:
            assert "redacted" in exchange.auth_value_preview


@pytest.mark.parametrize("artifact", ["01-flows.md", "02-ciphers.md", "03-findings.md"])
def test_markdown_tables_are_well_formed(analyze_capture, artifact: str) -> None:
    result = analyze_capture(fixture("weak_tls.pcap"))
    for line in (result.outdir / artifact).read_text().splitlines():
        if line.startswith("|") and "---" not in line:
            assert line.count("|") >= 3, f"ragged table row in {artifact}: {line!r}"


def test_empty_capture_does_not_crash(analyze_capture, tmp_path: Path) -> None:
    import struct

    from pcapforensics.pipeline import analyze

    empty = tmp_path / "empty.pcap"
    empty.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    result = analyze(empty, tmp_path / "empty-report")
    assert result.report.stats.packets == 0
    assert result.report.findings == []
    assert (result.outdir / "report.json").exists()
