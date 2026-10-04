"""TLS_LEGACY_RECORD_VERSION: a mandated sentinel is inventory, not a defect (#150).

The rule doc has always said the same thing -- "no action is required unless the legacy version
appears on post-handshake application records" -- and the detector never applied that distinction.
It fired on ``TlsSession.record_versions``, which is a de-duplicated list of version *names* that
keeps no frame number and no record content type, so the compatibility sentinel on a ClientHello
was indistinguishable from a downgraded application record. Across the 219-capture corpus that
was 26 findings in 17 captures, the most common code in the whole corpus, every one of them at
``low`` severity and ``high`` confidence.

These tests pin the decision recorded in docs/severity-model.md:

* the code still fires, because suppressing it would drop the genuine post-handshake case;
* it now reads as ``info``/``medium``, because the sentinel is a constant of the protocol rather
  than an observation about the traffic;
* confidence is not ``high``, because the index cannot say which record carried the value.

Assertions are on codes, severities and confidences -- never on prose, so rewording a summary
cannot break the suite while a change in what is detected still does.
"""

from __future__ import annotations

import re
from pathlib import Path

from conftest import codes, fixture, requires_tshark

DOC = Path(__file__).parent.parent / "src/pcapforensics/rule_docs/TLS_LEGACY_RECORD_VERSION.md"


def _index(*, negotiated: str, record_versions: list[str], frames: list[str],
           supported: list[str] | None = None):
    """A one-session index, built the way tests/test_detectors.py builds its own.

    ``record_versions`` is a plain list of names on purpose: that is all models.py keeps, and
    it is precisely why this detector cannot apply the post-handshake distinction.
    """
    from pcapforensics.detectors.tls_cipher import TlsCipherDetector
    from pcapforensics.index import CaptureIndex
    from pcapforensics.models import CaptureInfo, Flow, Handshake, TlsSession, endpoints_of, flow_key

    info = CaptureInfo(
        path="synthetic", name="synthetic", sha256="0" * 64, size_bytes=0,
        packets=len(frames), bytes=0, first_seen=0.0, last_seen=1.0, duration=1.0,
    )
    index = CaptureIndex(info)
    key = flow_key("tcp", "10.0.0.10", 40000, "10.0.0.20", 443)
    _proto, a, port_a, b, port_b = endpoints_of(key)
    index.flows[key] = Flow(key=key, proto="tcp", endpoint_a=a, port_a=port_a,
                            endpoint_b=b, port_b=port_b, app_proto="tls", first_frame=int(frames[0]))
    index.tls[key] = TlsSession(
        key=key,
        client_hello=Handshake(type=1, frame=int(frames[0]), legacy_version=negotiated,
                               supported_versions=supported or []),
        server_hello=Handshake(type=2, frame=int(frames[1]), legacy_version=negotiated,
                               supported_versions=supported or []),
        negotiated_version=negotiated,
        record_versions=record_versions,
        chosen_cipher=0x1301,  # TLS_AES_128_GCM_SHA256: strong, so no other finding interferes
        offered_ciphers=[0x1301],
        frames=[int(f) for f in frames],
        complete=True,
    )
    return TlsCipherDetector().detect(index)


@requires_tshark
def test_clienthello_sentinel_on_tls13_is_inventory_not_a_defect(analyze_capture) -> None:
    """TLS 1.3 negotiated, legacy value only on the ClientHello: reported, but as inventory."""
    result = analyze_capture(fixture("strong_tls13.pcap"))
    assert "TLS_LEGACY_RECORD_VERSION" in codes(result)
    [hit] = [f for f in result.report.findings if f.code == "TLS_LEGACY_RECORD_VERSION"]
    assert hit.severity == "info"
    assert hit.confidence == "medium"
    # The negotiated version is TLS 1.3 and that is still what the version rule reports.
    assert {s.negotiated_version for s in result.index.tls.values()} == {"TLS 1.3"}
    assert "TLS_VERSION_DEPRECATED" not in codes(result)


@requires_tshark
def test_clienthello_sentinel_on_tls12_is_inventory(analyze_capture) -> None:
    """A TLS 1.2 ClientHello carries no supported_versions, so 'absent' proves nothing (#150).

    This is the case that rules out firing only when supported_versions is missing: the sentinel
    is just as expected there, and the field is absent for protocol reasons, not suspicious ones.
    """
    result = analyze_capture(fixture("no_pfs_tls12.pcap"))
    assert "TLS_LEGACY_RECORD_VERSION" in codes(result)
    [hit] = [f for f in result.report.findings if f.code == "TLS_LEGACY_RECORD_VERSION"]
    assert hit.severity == "info"
    assert hit.confidence == "medium"


@requires_tshark
def test_post_handshake_application_record_still_fires(analyze_capture) -> None:
    """The genuine downgrade case must survive the demotion -- detection is not what is traded away.

    The index cannot mark a record as post-handshake, so this pins the shape the genuine case
    produces: the code still fires, and still carries the version as evidence.
    """
    result = analyze_capture(fixture("mixed_ciphers.pcap"))
    assert "TLS_LEGACY_RECORD_VERSION" in codes(result)
    [hit] = [f for f in result.report.findings if f.code == "TLS_LEGACY_RECORD_VERSION"]
    assert hit.severity == "info"
    assert [e.field for e in hit.evidence] == ["tls.record.version"]
    assert hit.evidence[0].frame > 0, "a finding must cite a real frame"


def test_legacy_value_equal_to_the_negotiated_version_is_not_reported_twice() -> None:
    """When the legacy value *is* the negotiated version, the deprecated-version rule owns it."""
    findings = _index(negotiated="TLS 1.0", record_versions=["TLS 1.0"], frames=["1", "2"])
    seen = {f.code for f in findings}
    assert "TLS_VERSION_DEPRECATED" in seen
    assert "TLS_LEGACY_RECORD_VERSION" not in seen


def test_modern_record_versions_never_fire() -> None:
    """No legacy value in the record layer means no finding, whatever the handshake looks like."""
    findings = _index(negotiated="TLS 1.2", record_versions=["TLS 1.2"], frames=["1", "2", "3"])
    assert "TLS_LEGACY_RECORD_VERSION" not in {f.code for f in findings}


def test_two_legacy_values_on_one_session_are_two_findings_not_one_blob() -> None:
    """Each legacy version is reported once, and ids stay distinct."""
    findings = _index(negotiated="TLS 1.2", record_versions=["TLS 1.0", "TLS 1.1", "TLS 1.2"],
                      frames=["1", "2", "3"])
    legacy = [f for f in findings if f.code == "TLS_LEGACY_RECORD_VERSION"]
    assert len(legacy) == 2
    assert len({f.id for f in legacy}) == 2


def test_two_sessions_do_not_collide_on_one_finding_id() -> None:
    """The scope keys on the session, so distinct flows get distinct ids."""
    first = _index(negotiated="TLS 1.3", record_versions=["TLS 1.0"], frames=["1", "2"])
    second = _index(negotiated="TLS 1.3", record_versions=["TLS 1.0"], frames=["10", "11", "12"])
    assert "TLS_LEGACY_RECORD_VERSION" in {f.code for f in first}
    assert "TLS_LEGACY_RECORD_VERSION" in {f.code for f in second}


def test_legacy_value_is_never_reported_as_high_confidence() -> None:
    """The index cannot say which record carried the value, so 'high' would be a rounded heuristic."""
    findings = _index(negotiated="TLS 1.3", record_versions=["TLS 1.0"], frames=["1", "2"],
                      supported=["TLS 1.3"])
    legacy = [f for f in findings if f.code == "TLS_LEGACY_RECORD_VERSION"]
    assert legacy and all(f.confidence != "high" for f in legacy)
    assert all(f.severity == "info" for f in legacy)


def test_cited_rfcs_are_declared_as_references() -> None:
    """Every RFC named in the finding text must also be in its references (tests/test_citations.py)."""
    findings = _index(negotiated="TLS 1.3", record_versions=["TLS 1.0"], frames=["1", "2"])
    rfc = re.compile(r"RFC \d+")
    for finding in findings:
        if finding.code != "TLS_LEGACY_RECORD_VERSION":
            continue
        cited = set(rfc.findall(f"{finding.summary} {finding.remediation or ''}"))
        assert cited, "the finding should cite the RFCs that make the value expected"
        assert cited <= set(rfc.findall(" ".join(finding.references))), cited


def test_rule_is_catalogued_and_documented() -> None:
    """The catalog entry and the four rule-doc sections stay in step with the detector."""
    from pcapforensics.rules import RULES

    assert "TLS_LEGACY_RECORD_VERSION" in RULES
    text = DOC.read_text()
    for section in ("## What it means", "## Why it matters", "## How to fix", "## How to verify"):
        assert section in text, section


def test_severity_model_records_the_decision() -> None:
    """docs/severity-model.md is where policy lives; the decision must be written down there."""
    policy = Path(__file__).parent.parent / "docs/severity-model.md"
    assert "TLS_LEGACY_RECORD_VERSION" in policy.read_text()
