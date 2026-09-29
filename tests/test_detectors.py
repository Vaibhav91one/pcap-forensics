"""End-to-end detector tests against the synthetic fixtures.

Each fixture exists to prove one thing. The assertions are on *finding codes*,
not on prose, so a rewording never breaks the suite and a regression in
detection always does.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import CAPTURES, FIXTURES, codes, fixture, load_json, requires_tshark

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


def test_scheme_less_authorization_never_reaches_a_report(analyze_capture) -> None:
    """A bare token has no scheme to keep; nothing of it may survive, in any case (issue #15)."""
    result = analyze_capture(fixture("http_bare_token.pcap"))
    assert "HTTP_CLEARTEXT_AUTH" in codes(result)
    joined = "".join(path.read_text() for path in result.artifacts).lower()
    assert "9f8e7d6c5b4a" not in joined, "part of the bare token leaked into a report"
    assert "pf-tok" not in joined, "the token prefix leaked into a report"
    assert "redacted" in joined, "the redaction notice is missing"


def test_external_resolvers_are_found_over_ipv4_and_ipv6(analyze_capture) -> None:
    """The resolver is the side on port 53/853, not the one that sorts last; internal and multicast never count (issue #6)."""
    result = analyze_capture(fixture("dns_external.pcap"))
    found = {tuple(f.subjects): f for f in result.report.findings if f.code == "DNS_EXTERNAL_RESOLVER"}
    assert set(found) == {("1.1.1.1",), ("2606:4700:4700::1111",)}
    assert found[("1.1.1.1",)].evidence[0].frame == 1
    assert found[("2606:4700:4700::1111",)].evidence[0].frame == 7


def test_dns_tunnel_is_attributed_to_the_querying_host() -> None:
    """The querier is the side not on port 53, whatever the address order; responses are not queries (issue #18)."""
    from pcapforensics.detectors.dns_quic_ssh import DnsQuicSshDetector
    from pcapforensics.index import CaptureIndex
    from pcapforensics.models import CaptureInfo, DnsQuery, Flow, endpoints_of, flow_key

    info = CaptureInfo(
        path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0,
        packets=48, bytes=0, first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    index = CaptureIndex(info)
    key = flow_key("udp", "10.0.0.10", 40000, "1.1.1.1", 53)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="udp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b, app_proto="dns", first_frame=1)
    for i in range(24):
        name = f"q{i:02d}a7f3c9.b5d2e8f4.c1a9e7b3.d6f2a8c4.tunnel.example"
        index.dns.append(DnsQuery(key=key, frame=2 * i + 1, name=name, qtype="TXT"))
        index.dns.append(DnsQuery(key=key, frame=2 * i + 2, name=name, qtype="TXT", is_response=True))
    (finding,) = [f for f in DnsQuicSshDetector().detect(index) if f.code == "DNS_TUNNEL_SHAPE"]
    assert finding.subjects == ["10.0.0.10"]
    assert all(item.frame % 2 == 1 for item in finding.evidence), "a response was counted as a query"


def test_ssh_weak_algorithms_are_flagged_only_on_the_legacy_session(analyze_capture) -> None:
    """Legacy KEXINIT raises all four SSH_WEAK_* codes; a modern one raises none (issue #8)."""
    result = analyze_capture(fixture("ssh_weak.pcap"))
    ssh = [f for f in result.report.findings if f.code.startswith("SSH_WEAK_")]
    legacy = {f.code: f for f in ssh if f.flow_key and ":43100<->" in f.flow_key}
    assert set(legacy) == {"SSH_WEAK_KEX", "SSH_WEAK_CIPHER", "SSH_WEAK_MAC", "SSH_WEAK_HOSTKEY"}
    assert legacy["SSH_WEAK_CIPHER"].evidence[0].value == "aes128-cbc"
    assert not [f for f in ssh if f.flow_key and ":43200<->" in f.flow_key], "modern SSH session flagged"


def test_syn_scan_shape(analyze_capture) -> None:
    result = analyze_capture(fixture("syn_scan.pcap"))
    assert "SYN_SCAN_SHAPE" in codes(result)
    (finding,) = [f for f in result.report.findings if f.code == "SYN_SCAN_SHAPE"]
    assert finding.subjects == ["10.0.0.10"]
    assert result.report.stats.flows == 39


def test_chacha20_is_not_a_weak_ssh_cipher() -> None:
    """ChaCha20-Poly1305 is a modern AEAD; only the CBC/RC4-era ciphers are weak (issue #2)."""
    from pcapforensics.detectors.dns_quic_ssh import WEAK_SSH_CIPHERS, DnsQuicSshDetector
    from pcapforensics.index import CaptureIndex
    from pcapforensics.models import CaptureInfo, Flow, SshSession, endpoints_of, flow_key

    assert "chacha20-poly1305@openssh.com" not in WEAK_SSH_CIPHERS
    info = CaptureInfo(
        path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0,
        packets=2, bytes=0, first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 51000, "10.0.0.20", 22)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b, app_proto="ssh", first_frame=1)
    index.ssh.append(SshSession(key=key, frame=4, ciphers=["chacha20-poly1305@openssh.com", "aes128-cbc"]))
    (finding,) = [f for f in DnsQuicSshDetector().detect(index) if f.code == "SSH_WEAK_CIPHER"]
    assert finding.evidence[0].value == "aes128-cbc"


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


@pytest.mark.parametrize(
    "pcap",
    sorted(FIXTURES.glob("*.pcap")) + sorted(CAPTURES.glob("*.pcap")) + sorted(CAPTURES.glob("*.pcapng")),
    ids=lambda p: p.name,
)
def test_every_finding_cites_a_real_frame(analyze_capture, pcap) -> None:
    """Evidence must point at a frame a reader can open in Wireshark (issue #4)."""
    result = analyze_capture(pcap)
    for finding in result.report.findings:
        assert finding.evidence, f"{finding.code} has no evidence"
        for item in finding.evidence:
            assert item.frame > 0, f"{finding.code} cites frame {item.frame}"


REFERENCE_FORMAT = re.compile(r"^(RFC \d+|CWE-\d+|CVE-\d{4}-\d{4,}|NIST SP .+|OWASP .+|JA3|docs/[\w./-]+\.md)$")


@pytest.mark.parametrize(
    "pcap",
    sorted(FIXTURES.glob("*.pcap")) + sorted(CAPTURES.glob("*.pcap")) + sorted(CAPTURES.glob("*.pcapng")),
    ids=lambda p: p.name,
)
def test_every_reference_is_well_formed(analyze_capture, pcap) -> None:
    """A reference must be something a reader can look up (issue #3)."""
    result = analyze_capture(pcap)
    for finding in result.report.findings:
        for ref in finding.references:
            assert REFERENCE_FORMAT.match(ref), f"{finding.code} cites {ref!r}"


def test_odd_port_reports_only_the_likely_server_side() -> None:
    """Both ports high: only the lower one is reported, at low confidence (issue #16)."""
    from pcapforensics.detectors.transport_exposure import TransportExposureDetector
    from pcapforensics.index import CaptureIndex
    from pcapforensics.models import CaptureInfo, Flow, endpoints_of, flow_key

    info = CaptureInfo(
        path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0,
        packets=2, bytes=0, first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 51000, "10.0.0.20", 2121)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(
        key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
        app_proto="ftp", first_frame=3, encrypted=False,
    )
    findings = [f for f in TransportExposureDetector().detect(index) if f.code == "SERVICE_ON_ODD_PORT"]
    assert len(findings) == 1
    (finding,) = findings
    assert finding.subjects == ["10.0.0.20"]
    assert finding.confidence == "low"
    assert (finding.evidence[0].frame, finding.evidence[0].field, finding.evidence[0].value) == (3, "tcp.port", "10.0.0.20:2121")


def test_tftp_ephemeral_ports_are_not_an_odd_port_service(analyze_capture) -> None:
    """tftp.pcap: client 63801 -> server 69 is not a service on an odd port (issue #16)."""
    pcap = CAPTURES / "tftp.pcap"
    if not pcap.exists():
        pytest.skip("tftp.pcap not in corpus")
    assert "SERVICE_ON_ODD_PORT" not in codes(analyze_capture(pcap))


def test_odd_port_ignores_flows_whose_server_port_is_well_known() -> None:
    """A standard port on either side means the service is not on an odd port (issue #16)."""
    from pcapforensics.detectors.transport_exposure import TransportExposureDetector
    from pcapforensics.index import CaptureIndex
    from pcapforensics.models import CaptureInfo, Flow, endpoints_of, flow_key

    info = CaptureInfo(
        path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0,
        packets=2, bytes=0, first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 5000, "10.0.0.20", 11211)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(
        key=key, proto="tcp", endpoint_a=a, port_a=port_a, endpoint_b=b, port_b=port_b,
        app_proto="redis", first_frame=1, encrypted=False,
    )
    assert not [f for f in TransportExposureDetector().detect(index) if f.code == "SERVICE_ON_ODD_PORT"]


def test_beaconing_needs_regular_gaps_not_just_a_low_rate(analyze_capture) -> None:
    """Same packet count and rate on both flows; only the fixed-period one is a beacon (issue #10)."""
    result = analyze_capture(fixture("beaconing.pcap"))
    beacons = {f.flow_key for f in result.report.findings if f.code == "BEACONING_SHAPE"}
    assert beacons == {"udp:10.0.0.10:50000<->203.0.113.5:8443"}
    flow = result.index.flows["udp:10.0.0.10:50000<->203.0.113.5:8443"]
    assert flow.burst_count == 10
    assert abs(flow.burst_gap_mean - 30.0) < 0.01


def test_well_known_ports_match_iana() -> None:
    """Pinned against IANA; a wrong entry mislabels flows and skews odd-port suppression (issue #23)."""
    from pcapforensics.index import WELL_KNOWN_PORTS

    assert WELL_KNOWN_PORTS[5060] == "sip"
    assert WELL_KNOWN_PORTS[5222] == "xmpp-client"
    assert WELL_KNOWN_PORTS[1194] == "openvpn"
    assert 506 not in WELL_KNOWN_PORTS
    assert 522 not in WELL_KNOWN_PORTS
