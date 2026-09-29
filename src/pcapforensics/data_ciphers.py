"""Cipher-suite registry access plus TLS crypto reasoning helpers.

Phase 0 owns this module. Detectors may only *read* it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from .models import TlsSession

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable

DATA_PATH = Path(__file__).parent / "data" / "cipher_suites.json"

SEVERITY_FOR_DEPRECATION = {
    "prohibited": "critical",
    "deprecated": "high",
    "legacy": "medium",
    "acceptable": "info",
    "recommended": "info",
}

VERSION_RANK: dict[str, int] = {
    "SSL 2.0": 0,
    "SSL 3.0": 10,
    "TLS 1.0": 20,
    "TLS 1.1": 30,
    "TLS 1.2": 40,
    "TLS 1.3": 50,
}


@dataclass(frozen=True)
class CipherSuite:
    id: int
    hex: str
    name: str
    kx: str
    enc: str
    mac: str
    prf: str
    forward_secrecy: bool
    tags: frozenset[str]
    deprecation: str

    @property
    def is_aead(self) -> bool:
        return "AEAD" in self.tags

    @property
    def severity(self) -> str:
        return SEVERITY_FOR_DEPRECATION.get(self.deprecation, "info")


class UnknownCipher(int):
    """An unrecognised suite id. Never silently accepted."""


@lru_cache(maxsize=1)
def registry() -> dict[int, CipherSuite]:
    payload = json.loads(DATA_PATH.read_text())
    out: dict[int, CipherSuite] = {}
    for key, entry in payload["suites"].items():
        out[int(key)] = CipherSuite(
            id=int(entry["id"]),
            hex=str(entry["hex"]),
            name=str(entry["name"]),
            kx=str(entry["kx"]),
            enc=str(entry["enc"]),
            mac=str(entry["mac"]),
            prf=str(entry.get("prf", "")),
            forward_secrecy=bool(entry["forward_secrecy"]),
            tags=frozenset(str(t) for t in entry["tags"]),
            deprecation=str(entry["deprecation"]),
        )
    return out


@lru_cache(maxsize=1)
def registry_provenance() -> list[str]:
    payload = json.loads(DATA_PATH.read_text())
    return [str(x) for x in payload.get("policy_provenance", [])]


def lookup(cipher_id: int | None) -> CipherSuite | None:
    if cipher_id is None:
        return None
    return registry().get(cipher_id)


def name_of(cipher_id: int | None) -> str:
    if cipher_id is None:
        return "none"
    suite = lookup(cipher_id)
    if suite is None:
        return f"UNKNOWN(0x{cipher_id:04x})"
    return suite.name


def classify(cipher_id: int | None) -> str:
    suite = lookup(cipher_id)
    return suite.deprecation if suite else "unknown"


def version_rank(version: str | None) -> int:
    if not version:
        return -1
    return VERSION_RANK.get(version, -1)


def is_deprecated_version(version: str | None) -> bool:
    return 0 <= version_rank(version) < VERSION_RANK["TLS 1.2"]


def forward_secrecy_for(session: TlsSession) -> tuple[bool | None, str]:
    """Decide PFS for a session. Returns ``(value, reason)``.

    ``None`` means "not decidable from this capture" -- truncated or encrypted
    handshakes, TLS 1.3 (always PFS by construction).
    """
    if session.proto == "dtls" and not session.client_hello:
        return None, "no ClientHello in capture"
    if session.negotiated_version and "1.3" in session.negotiated_version:
        return True, "TLS 1.3 mandates ephemeral key exchange"
    if session.chosen_cipher is None:
        if not session.offered_ciphers:
            return None, "handshake not visible in capture"
        return None, "ServerHello missing, chosen cipher unknown"
    suite = lookup(session.chosen_cipher)
    if suite is None:
        return None, f"cipher {name_of(session.chosen_cipher)} not in registry"
    if suite.kx == "tls13":
        return True, "TLS 1.3 cipher suite"
    if suite.forward_secrecy:
        return True, f"ephemeral key exchange ({suite.kx})"
    return False, f"static key exchange ({suite.kx}) -- no forward secrecy"


def weakness_reasons(cipher_id: int | None) -> list[str]:
    """Human-readable reasons a suite is weak, empty when nothing to report."""
    suite = lookup(cipher_id)
    if suite is None:
        return [f"cipher suite {name_of(cipher_id)} is not in the registry"]
    reasons: list[str] = []
    for tag in sorted(suite.tags):
        text = _TAG_TEXT.get(tag)
        if text:  # informational-only tags (PFS, TLS13) are not weaknesses
            reasons.append(text)
    if suite.deprecation == "prohibited":
        reasons.insert(0, "suite is prohibited by policy (RFC 8996 territory)")
    elif suite.deprecation == "deprecated":
        head = "static RSA key exchange" if suite.kx == "rsa" else f"non-ephemeral key exchange ({suite.kx})"
        reasons.insert(0, f"suite is deprecated: {head}")
    elif suite.deprecation == "legacy":
        reasons.insert(0, "suite is legacy (CBC or SHA-1 based)")
    return reasons


_TAG_TEXT = {
    "NULL_ENCRYPTION": "no encryption at all (NULL cipher)",
    "NULL_CIPHER": "NULL cipher: no confidentiality and no integrity",
    "EXPORT_GRADE": "export-grade key length, breakable by anyone",
    "RC4": "RC4 stream cipher is broken (RFC 7465)",
    "RC2": "RC2 is a legacy export-grade cipher",
    "DES": "single DES has a 56-bit key",
    "3DES": "3DES is vulnerable to Sweet32 (RFC 7457)",
    "IDEA": "IDEA is withdrawn and poorly implemented",
    "SEED": "SEED is a legacy Korean standard cipher",
    "MD5_MAC": "MD5 based MAC is collision-broken",
    "SHA1_MAC": "SHA-1 based MAC is deprecated (RFC 6194)",
    "CBC_MODE": "CBC mode suites carry Lucky13/Sweet32 padding risk",
    "NO_FORWARD_SECRECY": "no forward secrecy: static RSA/PSK key exchange",
    "STATIC_RSA": "RSA key exchange, no perfect forward secrecy",
    "ANONYMOUS": "anonymous key exchange, no authentication",
    "WEAK_KEY_BITS": "key length below 128 bits",
    "IOT": "constrained/IoT profile, verify device requirements",
    "SIGNALING": "signalling value, not a cipher suite",
    "PFS": "ephemeral key exchange, forward secrecy provided",
    "AES_CCM": "AES-CCM profile, verify the device requires it",
    "GOST": "GOST cipher, verify it is approved for your jurisdiction",
}


def rank_suites(cipher_ids: Iterable[int]) -> list[tuple[int, CipherSuite | None]]:
    """Chosen suites first, worst first -- the order a reviewer should read."""
    out = [(c, lookup(c)) for c in cipher_ids]
    order = {"unknown": 0, "prohibited": 1, "deprecated": 2, "legacy": 3, "acceptable": 4, "recommended": 5}
    return sorted(out, key=lambda pair: (order.get(pair[1].deprecation if pair[1] else "unknown", 0), pair[0]))
