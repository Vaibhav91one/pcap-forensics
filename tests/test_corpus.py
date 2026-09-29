"""Regression tests over the real capture corpus in ``captures/``.

These captures are the Wireshark project's own test files (BSD-licensed,
downloaded by ``scripts/fetch_captures.sh``). They are what stops the analyzer
from being a machine that only agrees with itself: every assertion here was
checked by hand against ``tshark -V`` output for the same capture.

Skipped automatically when ``captures/`` is empty, so a fresh clone still has a
green suite.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import CAPTURES, codes, requires_tshark

pytestmark = requires_tshark

pytestmark = pytest.mark.skipif(
    not CAPTURES.exists() or not any(CAPTURES.glob("*.pcap*")),
    reason="corpus not fetched; run scripts/fetch_captures.sh",
)


def capture(name: str) -> Path:
    path = CAPTURES / name
    if not path.exists():
        pytest.skip(f"{name} not in corpus")
    return path


def tshark_fields(pcap: Path, display_filter: str, *fields: str) -> list[list[str]]:
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-E", "aggregator=,"]
        + [item for field in fields for item in ("-e", field)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.splitlines()
    return [line.split("\t") for line in out]


# ------------------------------------------------------------------ crypto
def test_tls12_psk_ccm_is_flagged_weak_and_without_pfs(analyze_capture) -> None:
    pcap = capture("tls12-aes128ccm.pcap")
    result = analyze_capture(pcap)
    (session,) = result.index.tls.values()

    ground = tshark_fields(pcap, "tls.handshake.type==2", "tls.handshake.ciphersuite")[0]
    assert session.chosen_cipher == int(ground[0], 16) == 0xC0A4

    found = codes(result)
    assert "TLS_CIPHER_WEAK" in found
    assert "TLS_NO_FORWARD_SECRECY" in found
    # negotiated version really is TLS 1.2 even though the ClientHello record
    # layer says TLS 1.0 -- reporting that as "negotiated TLS 1.0" would be wrong
    assert session.negotiated_version == "TLS 1.2"
    assert "TLS_VERSION_DEPRECATED" not in found
    assert "TLS_LEGACY_RECORD_VERSION" in found


def test_tls13_capture_is_clean(analyze_capture) -> None:
    pcap = capture("tls13-rfc8446.pcap")
    result = analyze_capture(pcap)
    for session in result.index.tls.values():
        assert session.negotiated_version == "TLS 1.3"
        assert session.forward_secrecy is True
    # TLS 1.3 was negotiated and the session itself is fine ...
    assert not codes(result) & {
        "TLS_VERSION_DEPRECATED",
        "TLS_CIPHER_WEAK",
        "TLS_NO_FORWARD_SECRECY",
    }
    # ... but the client still offers 3DES and static-RSA suites for TLS 1.2,
    # which is downgrade surface. Verified against tshark: the ClientHello lists
    # 0x000a, 0x002f, 0x0035, 0x009c, 0x009d.
    assert "TLS_OFFERS_WEAK_CIPHERS" in codes(result)
    offered = {c for session in result.index.tls.values() for c in session.offered_ciphers}
    assert {0x000A, 0x002F, 0x0035} <= offered


def test_chacha_capture_matches_tshark_suites(analyze_capture) -> None:
    pcap = capture("tls12-chacha20poly1305.pcap")
    result = analyze_capture(pcap)
    ground = {
        int(row[0], 16)
        for row in tshark_fields(pcap, "tls.handshake.type==2", "tls.handshake.ciphersuite")
        if row and row[0]
    }
    chosen = {s.chosen_cipher for s in result.index.tls.values() if s.chosen_cipher is not None}
    assert chosen, "no negotiated cipher found"
    assert chosen <= ground
    # every suite in the registry, no UNKNOWN(...) -- that would mean a gap
    for session in result.index.tls.values():
        assert "UNKNOWN" not in _suite_name(session.chosen_cipher)
    assert "TLS_CIPHER_UNKNOWN" not in codes(result)


def _suite_name(cipher: int | None) -> str:
    from pcapforensics.data_ciphers import name_of

    return name_of(cipher)


def test_dtls10_capture_reports_deprecated_version(analyze_capture) -> None:
    pcap = capture("snakeoil-dtls.pcap")
    result = analyze_capture(pcap)
    (session,) = result.index.tls.values()
    assert session.proto == "dtls"
    assert session.negotiated_version == "DTLS 1.0"
    assert session.chosen_cipher == 0x0035  # TLS_RSA_WITH_AES_256_CBC_SHA
    found = codes(result)
    assert "TLS_VERSION_DEPRECATED" in found
    assert "TLS_CIPHER_WEAK" in found
    assert "TLS_NO_FORWARD_SECRECY" in found
    # the ClientHello offers RC4 and export-grade suites that were not chosen
    assert "TLS_OFFERS_WEAK_CIPHERS" in found
    assert 0x0004 in session.offered_ciphers  # TLS_RSA_WITH_RC4_128_MD5
    assert 0x0003 in session.offered_ciphers  # export RC4-40


def test_dtls12_capture_is_not_flagged_as_tls10(analyze_capture) -> None:
    pcap = capture("dtls12-aes128ccm8.pcap")
    result = analyze_capture(pcap)
    (session,) = result.index.tls.values()
    assert session.negotiated_version == "DTLS 1.2"
    assert "TLS_VERSION_DEPRECATED" not in codes(result)


def test_certificate_facts_come_from_openssl(analyze_capture) -> None:
    pcap = capture("dns-mdns.pcap")
    result = analyze_capture(pcap)
    sessions = [s for s in result.index.tls.values() if s.certs]
    if not sessions:
        pytest.skip("this tshark build did not dissect the certificate message")
    cert = sessions[0].certs[0]
    assert cert.subject and "immedia-semi.com" in cert.subject
    assert cert.issuer
    assert cert.public_key_bits == 2048
    assert cert.signature_algorithm_oid and "sha" in cert.signature_algorithm_oid.lower()
    assert cert.name_source == "openssl"
    assert cert.not_after
    # the chain really is two certificates in this capture
    assert len(sessions[0].certs) == 2


# ------------------------------------------------------------------- voice
def test_sip_rtp_capture_shows_unprotected_media(analyze_capture) -> None:
    pcap = capture("sip-rtp.pcapng")
    result = analyze_capture(pcap)
    found = codes(result)
    assert "SIP_CLEARTEXT_SIGNALLING" in found
    assert "RTP_MEDIA_UNPROTECTED" in found
    assert "SDP_NO_CRYPTO_ATTR" in found
    assert result.report.stats.rtp_streams >= 1
    ground = tshark_fields(pcap, "rtp", "rtp.ssrc")
    assert ground, "tshark found no RTP either"
    ssrcs = {s.ssrc for s in result.index.rtp}
    assert ssrcs <= {int(row[0], 16) for row in ground if row and row[0]}


def test_sip_only_capture_has_no_media_findings(analyze_capture) -> None:
    pcap = capture("sip.pcapng")
    result = analyze_capture(pcap)
    assert "SIP_CLEARTEXT_SIGNALLING" in codes(result)
    assert "RTP_MEDIA_UNPROTECTED" not in codes(result)
    assert result.report.stats.rtp_streams == 0


# --------------------------------------------------------------------- dns
def test_mdns_capture_lists_the_resolver(analyze_capture) -> None:
    pcap = capture("dns_port.pcap")
    result = analyze_capture(pcap)
    assert result.report.stats.dns_queries >= 1
    assert "DNS_CLEARTEXT" in codes(result)
    names = {q.name for q in result.index.dns}
    ground = tshark_fields(pcap, "dns.qry.name", "dns.qry.name")
    assert names <= {row[0] for row in ground if row and row[0]}


# ------------------------------------------------------------------- quic
def test_quic_capture_is_reported_as_opaque(analyze_capture) -> None:
    pcap = capture("quic-with-secrets.pcapng")
    result = analyze_capture(pcap)
    assert result.report.stats.quic_sessions >= 1
    assert "QUIC_PAYLOAD_OPAQUE" in codes(result)
    session = result.index.quic[0]
    assert session.sni == "cloudflare-quic.com"
    assert session.tls_versions  # inner TLS versions were visible
    assert any("QUIC SNI observed" in note for note in result.report.notes)


# ------------------------------------------------------------- no crashers
@pytest.mark.parametrize(
    "name",
    [
        "ntp.pcap",
        "tftp.pcap",
        "retrans-tls.pcap",
        "tls-renegotiation.pcap",
        "sip.pcapng",
        "sip-rtp.pcapng",
        "dns-mdns.pcap",
        "quic-with-secrets.pcapng",
    ],
)
def test_corpus_capture_produces_a_complete_report(analyze_capture, name: str) -> None:
    """Whatever the capture, the run must finish and write all six artifacts."""
    result = analyze_capture(capture(name))
    for path in result.artifacts:
        assert path.exists() and path.stat().st_size > 0, path.name
    assert result.report.capture.packets > 0
    assert result.report.detector_versions, "no detector ran"


def test_retransmitted_handshake_does_not_duplicate_findings(analyze_capture) -> None:
    pcap = capture("tls-renegotiation.pcap")
    result = analyze_capture(pcap)
    ids = [f.id for f in result.report.findings]
    assert len(ids) == len(set(ids)), "duplicate finding ids"
    assert len(result.index.tls) == 1


# ------------------------------------------------- certificate policy tests
def test_modern_ec_certificate_is_not_flagged_weak(analyze_capture) -> None:
    """A P-384 EC key is stronger than RSA-2048.

    A blanket "<2048 bits is weak" rule produced a false high-severity finding on
    every modern EC certificate before this was fixed.
    """
    pcap = capture("tls12-chacha20poly1305.pcap")
    result = analyze_capture(pcap)
    sessions = [s for s in result.index.tls.values() if s.certs]
    if not sessions:
        pytest.skip("no certificate in this capture for this tshark build")
    cert = sessions[0].certs[0]
    assert cert.key_algorithm and "ec" in cert.key_algorithm.lower()
    assert cert.public_key_bits == 384
    assert "TLS_CERT_WEAK_KEY" not in codes(result)


def test_expiry_is_judged_against_the_capture_window(analyze_capture) -> None:
    """A 2017 capture with a 30-day certificate must not read as 'expired 3000 days ago'."""
    pcap = capture("tls12-chacha20poly1305.pcap")
    result = analyze_capture(pcap)
    found = codes(result)
    assert "TLS_CERT_EXPIRED" not in found
    expiring_now = [f for f in result.report.findings if f.code == "TLS_CERT_EXPIRED_NOW"]
    for finding in expiring_now:
        assert finding.severity == "low"
        assert "valid during the capture" in finding.title


def test_weak_key_policy_per_algorithm() -> None:
    from pcapforensics.detectors.tls_cipher import weak_key_verdict

    # RSA thresholds
    assert weak_key_verdict("rsaEncryption", 512) is not None
    assert weak_key_verdict("rsaEncryption", 512)[0] == "high"
    assert weak_key_verdict("rsaEncryption", 1024)[0] == "medium"
    assert weak_key_verdict("rsaEncryption", 2048) is None
    assert weak_key_verdict("rsaEncryption", 4096) is None
    # EC thresholds are curve-based, not RSA thresholds
    assert weak_key_verdict("id-ecPublicKey", 256) is None
    assert weak_key_verdict("id-ecPublicKey", 384) is None
    assert weak_key_verdict("id-ecPublicKey", 521) is None
    assert weak_key_verdict("id-ecPublicKey", 192)[0] == "high"
    assert weak_key_verdict("id-ecPublicKey", 224)[0] == "medium"
    # unknown algorithm: apply the RSA rule and say so
    assert weak_key_verdict(None, 1024)[0] == "medium"
    assert weak_key_verdict(None, None) is None
