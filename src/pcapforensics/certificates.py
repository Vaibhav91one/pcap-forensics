"""Certificate enrichment via the local ``openssl`` binary.

tshark flattens X.509 into a bag of RDN strings with no subject/issuer split and
no reliable key size, so anything that needs real certificate facts goes
through openssl instead:

    tls.handshake.certificate  ->  raw DER (one field occurrence per cert)
    DER                       ->  PEM  ->  `openssl x509 -noout -text`

Everything is best effort. If openssl is missing or a cert is unparseable the
caller keeps the tshark-derived values and records a note -- never a guess.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import shutil
import ssl
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .models import Cert

MAX_CERTS_PER_RUN = 60
OPENSSL_TIMEOUT = 10

# `-text -nameopt RFC2253` prints indented "Subject:"/"Issuer:"; the plain
# `-subject`/`-issuer` flags print "subject="/"issuer=". Accept both.
SUBJECT_RE = re.compile(r"^\s*(?:subject=|Subject:)\s*(\S.*)$", re.MULTILINE)
ISSUER_RE = re.compile(r"^\s*(?:issuer=|Issuer:)\s*(\S.*)$", re.MULTILINE)
NOT_BEFORE_RE = re.compile(r"^\s*Not Before\s*:\s*(.+)$", re.MULTILINE)
NOT_AFTER_RE = re.compile(r"^\s*Not After\s*:\s*(.+)$", re.MULTILINE)
KEYBITS_RE = re.compile(r"Public-Key:\s*\((\d+)\s*bit", re.MULTILINE)
KEYALG_RE = re.compile(r"^\s*Public Key Algorithm:\s*(\S+)", re.MULTILINE)
CURVE_RE = re.compile(r"^\s*(?:ASN1 OID|NIST CURVE):\s*(\S+)", re.MULTILINE)
SIGALG_RE = re.compile(r"^\s*Signature Algorithm:\s*(\S+)", re.MULTILINE)
SAN_RE = re.compile(r"DNS:([^,\s]+)")
CA_RE = re.compile(r"^\s*CA:(TRUE|FALSE)", re.MULTILINE)
SERIAL_RE = re.compile(r"^\s*Serial Number:\s*(\S+)", re.MULTILINE)


@lru_cache(maxsize=1)
def openssl_path() -> str | None:
    return shutil.which("openssl")


def spki_sha256(pubkey_der: bytes) -> str:
    """Fingerprint a DER SubjectPublicKeyInfo: sha256(DER)[:16].

    Non-secret and identical whether the public key comes from a capture's
    certificate or a private key found in firmware, so the two can be matched.
    """
    return hashlib.sha256(pubkey_der).hexdigest()[:16]


def _spki_from_cert_pem(pem: str) -> str | None:
    """PEM certificate -> its public-key SPKI fingerprint, via openssl."""
    path = openssl_path()
    if path is None:
        return None
    try:
        proc = subprocess.run(
            [path, "x509", "-pubkey", "-noout"],
            input=pem,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except subprocess.SubprocessError:
        return None
    if proc.returncode != 0:
        return None
    body = "".join(
        line for line in proc.stdout.splitlines() if line and not line.startswith("-----")
    )
    try:
        return spki_sha256(base64.b64decode(body))
    except (ValueError, binascii.Error):
        return None


@dataclass
class CertFacts:
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    public_key_bits: int | None = None
    key_algorithm: str | None = None
    key_curve: str | None = None
    spki_sha256: str | None = None
    signature_algorithm: str | None = None
    san_dns: list[str] = field(default_factory=list)
    is_ca: bool | None = None
    serial: str | None = None
    self_signed: bool | None = None
    error: str | None = None


def _normalise_dn(dn: str) -> str:
    return re.sub(r"\s+", " ", dn.strip().lower())


def parse_openssl_text(text: str) -> CertFacts:
    facts = CertFacts()
    subject = SUBJECT_RE.search(text)
    issuer = ISSUER_RE.search(text)
    facts.subject = subject.group(1).strip() if subject else None
    facts.issuer = issuer.group(1).strip() if issuer else None
    not_before = NOT_BEFORE_RE.search(text)
    not_after = NOT_AFTER_RE.search(text)
    facts.not_before = not_before.group(1).strip() if not_before else None
    facts.not_after = not_after.group(1).strip() if not_after else None
    keybits = KEYBITS_RE.search(text)
    facts.public_key_bits = int(keybits.group(1)) if keybits else None
    keyalg = KEYALG_RE.search(text)
    facts.key_algorithm = keyalg.group(1) if keyalg else None
    curve = CURVE_RE.search(text)
    facts.key_curve = curve.group(1) if curve else None
    sigalgs = SIGALG_RE.findall(text)
    facts.signature_algorithm = sigalgs[0] if sigalgs else None
    facts.san_dns = [d.strip() for d in SAN_RE.findall(text) if d.strip()]
    ca = CA_RE.search(text)
    facts.is_ca = ca.group(1) == "TRUE" if ca else None
    serial = SERIAL_RE.search(text)
    facts.serial = serial.group(1) if serial else None
    if facts.subject and facts.issuer:
        facts.self_signed = _normalise_dn(facts.subject) == _normalise_dn(facts.issuer)
    return facts


def inspect_der(der: bytes) -> CertFacts:
    """DER bytes -> :class:`CertFacts`."""
    path = openssl_path()
    if path is None:
        return CertFacts(error="openssl not available")
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except Exception as exc:
        return CertFacts(error=f"DER->PEM failed: {exc}")
    try:
        proc = subprocess.run(
            [path, "x509", "-noout", "-text", "-nameopt", "RFC2253"],
            input=pem,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except subprocess.SubprocessError as exc:
        return CertFacts(error=f"openssl failed: {exc}")
    if proc.returncode != 0:
        return CertFacts(error=f"openssl exit {proc.returncode}: {proc.stderr.strip()[:120]}")
    facts = parse_openssl_text(proc.stdout)
    facts.spki_sha256 = _spki_from_cert_pem(pem)
    return facts


def split_certificate_occurrences(values: list[str]) -> list[bytes]:
    """tshark yields one hex blob per certificate, sometimes comma-joined."""
    out: list[bytes] = []
    for chunk in values:
        for part in chunk.split(","):
            part = part.strip().replace(":", "")
            if not part or len(part) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", part):
                continue
            out.append(bytes.fromhex(part))
    return out


def enrich_all(hex_values: list[str], budget: int = MAX_CERTS_PER_RUN) -> tuple[list[CertFacts], list[str]]:
    """Returns (facts per certificate, list of human-readable problems)."""
    ders = split_certificate_occurrences(hex_values)
    notes: list[str] = []
    if not ders:
        return [], notes
    if openssl_path() is None:
        return [], ["openssl not found: certificate subject/issuer/key size unavailable"]
    if len(ders) > budget:
        notes.append(
            f"certificate enrichment capped at {budget} of {len(ders)} certificates "
            "(raise MAX_CERTS_PER_RUN if you need them all)"
        )
        ders = ders[:budget]
    facts: list[CertFacts] = []
    for der in ders:
        result = inspect_der(der)
        if result.error:
            notes.append(f"certificate parse: {result.error}")
        facts.append(result)
    return facts, notes


def apply_openssl_facts(certs: list[Cert], facts: list[CertFacts]) -> None:
    """Overlay openssl facts onto tshark-derived certs, in chain order."""
    if not facts:
        return
    for cert, fact in zip(certs, facts, strict=False):
        if fact.subject:
            cert.subject = fact.subject
        if fact.issuer:
            cert.issuer = fact.issuer
        if fact.not_before:
            cert.not_before = fact.not_before
        if fact.not_after:
            cert.not_after = fact.not_after
        if fact.public_key_bits:
            cert.public_key_bits = fact.public_key_bits
        if fact.key_algorithm:
            cert.key_algorithm = fact.key_algorithm
        if fact.key_curve:
            cert.key_curve = fact.key_curve
        if fact.spki_sha256:
            cert.spki_sha256 = fact.spki_sha256
        if fact.signature_algorithm:
            cert.signature_algorithm_oid = fact.signature_algorithm
        if fact.san_dns:
            cert.san_dns = fact.san_dns
        if fact.self_signed is not None:
            cert.self_signed_suspected = fact.self_signed
        if fact.subject:
            cert.name_source = "openssl"
    if len(certs) > len(facts):
        for cert in certs[len(facts) :]:
            cert.name_source = "tshark-flattened"
