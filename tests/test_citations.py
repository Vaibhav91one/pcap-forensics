"""Finding text cites only RFCs listed in its references, and no phantom RFC appendix is cited (issue #72)."""

from __future__ import annotations

import re

import pytest

from conftest import FIXTURES, ROOT, requires_tshark
from pcap_doctor.detectors.tls_cipher import VERSION_FINDING, version_references

RFC = re.compile(r"RFC \d+")


def test_version_texts_cite_only_their_references() -> None:
    for version, (_severity, text) in VERSION_FINDING.items():
        assert set(RFC.findall(text)) <= set(version_references(version)), version


@pytest.mark.parametrize(
    "path",
    [
        "src/pcap_doctor/detectors/tls_cipher.py",
        "src/pcap_doctor/data_ciphers.py",
        "src/pcap_doctor/data/cipher_suites.json",
        "scripts/gen_cipher_suites.py",
        "docs/cipher-policy.md",
    ],
)
def test_no_phantom_citations(path: str) -> None:
    text = (ROOT / path).read_text()
    for phantom in ("RFC 8999", "8996 Appendix", "8996 App.", "8996 territory"):
        assert phantom not in text, f"{path}: {phantom}"


@requires_tshark
def test_every_fixture_finding_cites_only_its_references(analyze_capture) -> None:
    for pcap in sorted(FIXTURES.glob("*.pcap")):
        for finding in analyze_capture(pcap).report.findings:
            cited = set(RFC.findall(f"{finding.summary} {finding.remediation or ''}"))
            assert cited <= set(RFC.findall(" ".join(finding.references))), (pcap.name, finding.code)
