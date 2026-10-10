"""The rule catalog covers exactly the codes the detectors can emit (issue #47)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import CAPTURES, FIXTURES, codes, requires_tshark
from pcap_doctor.registry import all_detectors
from pcap_doctor.rules import CATEGORIES, RULES, category_of

DETECTORS = Path(__file__).resolve().parents[1] / "src" / "pcap_doctor" / "detectors"
CODE_LITERAL = re.compile(r'"((?:TLS|HTTP|CLEARTEXT|DNS|QUIC|RTP|SDP|SERVICE|SIP|SSH|SYN|BEACONING|SIGNATURE|SMB1?)_[A-Z0-9_]+)"')
#: Built with an f-string in dns_quic_ssh.py (``SSH_WEAK_{kind.upper()}``), so no literal exists.
SSH_WEAK = {"SSH_WEAK_KEX", "SSH_WEAK_CIPHER", "SSH_WEAK_MAC", "SSH_WEAK_HOSTKEY"}


def _codes_in_detector_source() -> set[str]:
    found: set[str] = set()
    for path in DETECTORS.glob("*.py"):
        if not path.name.startswith("_"):
            found |= set(CODE_LITERAL.findall(path.read_text()))
    return found | SSH_WEAK


def test_catalog_matches_the_detector_source() -> None:
    assert set(RULES) == _codes_in_detector_source()


def test_every_rule_has_a_real_detector_category_and_title() -> None:
    detectors = {d.name for d in all_detectors()}
    for rule in RULES.values():
        assert rule.detector in detectors, rule.code
        assert rule.category in CATEGORIES and rule.category != "Other", rule.code
        assert rule.title, rule.code


def test_unknown_code_falls_back_to_other() -> None:
    assert category_of("NOT_A_CODE") == "Other"
    assert category_of("DNS_CLEARTEXT") == "DNS"


@requires_tshark
@pytest.mark.parametrize(
    "pcap",
    sorted(FIXTURES.glob("*.pcap")) + sorted(CAPTURES.glob("*.pcap")) + sorted(CAPTURES.glob("*.pcapng")),
    ids=lambda p: p.name,
)
def test_every_produced_code_is_catalogued(analyze_capture, pcap) -> None:
    assert codes(analyze_capture(pcap)) <= set(RULES)
