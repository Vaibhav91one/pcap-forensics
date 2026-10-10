"""Cipher-suite registry: names, derivation and policy.

These are the tests that would have caught the original hand-written suite
table, which had 22 wrong cipher ids before it was replaced by derivation from
tshark's own value table.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pcap_doctor.data_ciphers import (
    classify,
    forward_secrecy_for,
    is_deprecated_version,
    lookup,
    name_of,
    rank_suites,
    registry,
    version_rank,
    weakness_reasons,
)
from pcap_doctor.models import TlsSession, flow_key

NAMES_TSV = Path(__file__).resolve().parents[1] / "src" / "pcap_doctor" / "data" / "cipher_names.tsv"
JSON_PATH = Path(__file__).resolve().parents[1] / "src" / "pcap_doctor" / "data" / "cipher_suites.json"


def _names() -> dict[int, str]:
    out: dict[int, str] = {}
    for line in NAMES_TSV.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        raw, _, name = line.partition("\t")
        out[int(raw)] = name.strip()
    return out


def test_registry_covers_every_name_in_the_tsv() -> None:
    reg = registry()
    missing = {i: n for i, n in _names().items() if i not in reg}
    assert not missing, f"registry is missing {len(missing)} suites, e.g. {list(missing.items())[:5]}"


def test_registry_names_match_the_vendored_tsv() -> None:
    for cipher_id, name in _names().items():
        suite = lookup(cipher_id)
        assert suite is not None, cipher_id
        assert suite.name == name, f"{cipher_id:#06x}: {suite.name!r} != {name!r}"


def test_tls13_suites_are_recommended_and_forward_secret() -> None:
    for cipher_id in (0x1301, 0x1302, 0x1303, 0x1304, 0x1305):
        suite = lookup(cipher_id)
        assert suite is not None
        assert suite.deprecation == "recommended"
        assert suite.forward_secrecy is True
        assert "TLS13" in suite.tags


@pytest.mark.parametrize(
    ("cipher_id", "deprecation", "forward_secrecy"),
    [
        (0x002F, "deprecated", False),  # TLS_RSA_WITH_AES_128_CBC_SHA
        (0x0035, "deprecated", False),  # TLS_RSA_WITH_AES_256_CBC_SHA
        (0x0033, "legacy", True),  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        (0x0067, "legacy", True),  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        (0xC02F, "acceptable", True),  # ECDHE_RSA_AES_128_GCM_SHA256
        (0xCCA8, "acceptable", True),  # ECDHE_RSA_CHACHA20_POLY1305_SHA256
        (0xCCA9, "acceptable", True),  # ECDHE_ECDSA_CHACHA20_POLY1305_SHA256
        (0x0003, "prohibited", False),  # export RC4-40
        (0x0004, "prohibited", False),  # RC4_128_MD5
        (0x0005, "prohibited", False),  # RC4_128_SHA
        (0x000A, "prohibited", False),  # RSA 3DES
    ],
)
def test_known_suites_are_classified_as_documented(cipher_id: int, deprecation: str, forward_secrecy: bool) -> None:
    suite = lookup(cipher_id)
    assert suite is not None, f"{cipher_id:#06x} missing from registry"
    assert suite.deprecation == deprecation
    assert suite.forward_secrecy is forward_secrecy


def test_unknown_cipher_is_reported_not_silently_accepted() -> None:
    assert lookup(0xDEAD) is None
    assert "UNKNOWN" in name_of(0xDEAD)
    assert classify(0xDEAD) == "unknown"
    assert weakness_reasons(0xDEAD)


def test_signalling_values_are_not_ciphers() -> None:
    assert lookup(0x00FF) is None or lookup(0x00FF).deprecation == "signalling"
    assert classify(0x00FF) in {"signalling", "unknown"}


def test_weakness_reasons_are_human_readable() -> None:
    reasons = weakness_reasons(0x002F)
    assert any("forward secrecy" in r for r in reasons)
    assert all(len(r) > 8 for r in reasons)


def test_rank_suites_puts_worst_first() -> None:
    ranked = rank_suites([0x1301, 0x002F, 0x0004])
    assert [c for c, _ in ranked] == [0x0004, 0x002F, 0x1301]


def test_version_ranking_and_deprecation() -> None:
    assert version_rank("TLS 1.0") < version_rank("TLS 1.2") < version_rank("TLS 1.3")
    assert is_deprecated_version("TLS 1.0")
    assert is_deprecated_version("TLS 1.1")
    assert not is_deprecated_version("TLS 1.2")
    assert not is_deprecated_version("TLS 1.3")


def _session(chosen: int | None, version: str = "TLS 1.2") -> TlsSession:
    return TlsSession(
        key=flow_key("tcp", "10.0.0.1", 1234, "10.0.0.2", 443),
        negotiated_version=version,
        chosen_cipher=chosen,
        offered_ciphers=[chosen] if chosen else [],
    )


def test_forward_secrecy_reasoning() -> None:
    pfs, reason = forward_secrecy_for(_session(0xC02F))
    assert pfs is True and "ephemeral" in reason

    pfs, reason = forward_secrecy_for(_session(0x002F))
    assert pfs is False and "static" in reason

    pfs, _ = forward_secrecy_for(_session(0x1301, version="TLS 1.3"))
    assert pfs is True

    pfs, reason = forward_secrecy_for(_session(None))
    assert pfs is None and reason


def test_generated_json_is_in_sync_with_the_loader() -> None:
    payload = json.loads(JSON_PATH.read_text())
    reg = registry()
    assert set(payload["suites"]) == {str(i) for i in reg}
    for key, entry in payload["suites"].items():
        assert entry["name"] == reg[int(key)].name
        assert entry["deprecation"] == reg[int(key)].deprecation
