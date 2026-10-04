"""``keys scan``: inventory the key material in an already-extracted firmware tree (issue #117, Phase B).

Authorized white-box testing. The input is a filesystem tree (e.g. an unpacked firmware image); pcap-doctor
never unpacks or executes firmware. It classifies every PEM private key and certificate, flags the dangerous
ones (weak key, self-signed, expired, and — critically — a private key whose public half matches a shipped
certificate, meaning the operator *holds the key for that cert*), and can normalise the private keys into a
directory that ``analyze --keys-from`` consumes to decrypt a capture.

Private-key **bytes are never printed** — only paths, types, sizes and the public SPKI fingerprint (a
non-secret SHA-256 of the DER public key), which is also what ``analyze`` matches against a capture's server
certificate.
"""

from __future__ import annotations

import hashlib
import json as jsonlib
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.table import Table

from ..certificates import openssl_path, parse_openssl_text
from ._console import console

keys_app = typer.Typer(help="Inspect key material in an extracted firmware tree.", no_args_is_help=True)

KEY_EXT = (".pem", ".key", ".der", ".crt", ".cer")
WEAK_BITS = 1024  # RSA <= 1024 bits is breakable; flag it

# `bits` is an RSA modulus size, and only an RSA modulus size: WEAK_BITS is an RSA threshold. openssl
# reports every public key type through the same "Public-Key: (N bit)" line, but the number means
# something different for each — a curve size for EC, a prime size for DSA — so the algorithm is what
# decides whether the number may be compared against WEAK_BITS at all. See _cert_rsa_bits for the
# certificate path and _read_key_text for the private-key path: both set `bits` for RSA alone, so the
# one comparison in _flag is an RSA statement by construction rather than by a second guess at the type.
RSA_PUBLIC_KEY_ALGS = frozenset({"rsaEncryption", "rsassaPss"})

# Algorithms whose strength this command can decide. RSA is judged on its modulus against WEAK_BITS.
# Ed25519 and Ed448 are not parameterised by a secret size at all — RFC 8032 fixes the curve — so there
# is no number to brute-force and no threshold to apply. Everything else (EC, DSA, and any key type
# openssl describes in a way we do not recognise) is reported undecided by _flag rather than judged
# by the RSA rule or silently passed over as acceptable (AGENTS.md section 4).
DECIDED_ALGORITHMS = frozenset({"RSA", "ED25519", "ED448"})


@dataclass
class KeyEntry:
    path: str  # relative to the scanned root
    kind: str  # "private-key" or "certificate"
    algorithm: str | None = None  # RSA / EC / DSA / ED25519 / ED448, or None if unreadable
    bits: int | None = None  # an RSA modulus size, and only ever one — see WEAK_BITS
    encrypted: bool = False
    common_name: str | None = None
    self_signed: bool | None = None
    not_after: str | None = None
    expired: bool | None = None
    spki: str | None = None  # sha256(DER public key)[:16] — non-secret
    flags: list[str] = field(default_factory=list)


def _ossl(args: list[str], data: bytes | None = None) -> tuple[int, bytes]:
    exe = openssl_path()
    if exe is None:
        return 1, b""
    try:
        r = subprocess.run([exe, *args], input=data, capture_output=True, timeout=15, check=False)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, b""


def _spki_of_pubkey_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()[:16]


def _read_key_text(text: str) -> tuple[str | None, int | None]:
    """``(algorithm, RSA modulus size)`` read out of an ``openssl pkey -text`` dump (#144).

    openssl prints the same ``Private-Key: (N bit)`` line for every key type, and N is a different
    quantity in each: a modulus for RSA, a curve size for EC, a prime size for DSA. Only the RSA
    modulus is returned, because only that is the quantity ``WEAK_BITS`` is a threshold for — handing
    the curve size of a NIST-recommended P-256 key to an RSA breakability threshold reports a key
    roughly as strong as RSA-3072 as weak.

    Each algorithm is recognised from a marker openssl prints for that algorithm alone, and a key
    matching none of them comes back as ``None`` rather than being assumed to be RSA: an unplaceable
    key is then reported undecided by ``_flag``, which is honest, where a default of "RSA" would call
    a strong key breakable (AGENTS.md section 4). The size of an EC curve is deliberately not
    returned; judging curves is a policy this module does not have, and guessing one here would put it
    nowhere (#144).
    """
    size = re.search(r"\((\d+)\s*bit", text)  # "Private-Key: (512 bit, 2 primes)"
    modulus = int(size.group(1)) if size else None
    header = text.lstrip().partition("\n")[0]
    if header.startswith(("ED25519", "ED448")):
        return header.partition(" ")[0], None  # "ED25519 Private-Key:" — fixed-parameter, no size
    if "ASN1 OID:" in text:  # every EC key: "ASN1 OID: prime256v1", "ASN1 OID: brainpoolP256r1"
        return "EC", None
    if all(re.search(rf"^{name}:\s*$", text, re.M) for name in ("P", "Q", "G")):  # DSA prints p, q, g
        return "DSA", None
    if "modulus:" in text and "publicExponent:" in text:  # RSA alone
        return "RSA", modulus
    return None, None


def _classify_private_key(path: Path) -> KeyEntry:
    e = KeyEntry(path="", kind="private-key")
    rc, out = _ossl(["pkey", "-in", str(path), "-noout", "-text"])
    if rc != 0:
        rc, out = _ossl(["rsa", "-in", str(path), "-noout", "-text", "-passin", "pass:"])
    if rc != 0:
        e.encrypted = True  # a key we can't read without a passphrase (still: key material is present)
        return e
    e.algorithm, e.bits = _read_key_text(out.decode("latin-1"))
    rc, pub = _ossl(["pkey", "-in", str(path), "-pubout", "-outform", "DER"])
    if rc != 0:
        rc, pub = _ossl(["rsa", "-in", str(path), "-pubout", "-outform", "DER", "-passin", "pass:"])
    if rc == 0 and pub:
        e.spki = _spki_of_pubkey_der(pub)
    return e


def _classify_cert(path: Path) -> KeyEntry | None:
    rc, out = _ossl(["x509", "-in", str(path), "-noout", "-subject", "-issuer", "-enddate", "-nameopt", "RFC2253"])
    if rc != 0:
        return None
    e = KeyEntry(path="", kind="certificate")
    fields = {k: v for k, _, v in (line.partition("=") for line in out.decode("latin-1").splitlines())}

    def cn(dn: str) -> str | None:
        for part in dn.split(","):
            if part.strip().startswith("CN="):
                return part.strip()[3:]
        return dn.strip()[:60] or None

    subject, issuer = fields.get("subject", ""), fields.get("issuer", "")
    e.common_name = cn(subject)
    e.self_signed = subject.strip() == issuer.strip() and bool(subject.strip())
    e.not_after = fields.get("notAfter", "").strip() or None
    rc2, pub = _ossl(["x509", "-in", str(path), "-pubkey", "-noout"])
    if rc2 == 0 and pub:
        rc3, der = _ossl(["pkey", "-pubin", "-outform", "DER"], pub)
        if rc3 == 0 and der:
            e.spki = _spki_of_pubkey_der(der)
    _cert_rsa_bits(e, path)
    return e


def _cert_rsa_bits(e: KeyEntry, path: Path) -> None:
    """Read a shipped certificate's RSA modulus size into ``e.bits`` (#143).

    A certificate carries no key file to read, so this is where ``keys scan`` learns how big the key
    it ships is — without it a 768-bit certificate reads as merely "private-key-present". openssl
    reports the size as "Public-Key: (768 bit)", but it prints that same line for an EC key with the
    curve size, where 256 is a *strong* key, and for a DSA key with a prime size. Handing either to
    ``_flag``'s RSA threshold is issue #144, so those certificates keep ``bits=None`` here rather
    than acquiring a number that would read as a breakable RSA key.

    A certificate whose key size cannot be read keeps ``bits=None`` and is not flagged weak: an
    unreadable key size is not a weak key, and guessing one would invent a fact the file does not
    contain (AGENTS.md section 4).
    """
    rc, text = _ossl(["x509", "-in", str(path), "-noout", "-text"])
    if rc != 0:
        return
    facts = parse_openssl_text(text.decode("latin-1"))
    if facts.key_algorithm in RSA_PUBLIC_KEY_ALGS:
        e.bits = facts.public_key_bits


def _is_private_key(path: Path) -> bool:
    try:
        return "PRIVATE KEY" in path.read_text(encoding="latin-1", errors="ignore")[:4096]
    except OSError:
        return False


def scan(root: Path) -> list[KeyEntry]:
    """Every private key and certificate under ``root``, classified and risk-flagged."""
    entries: list[KeyEntry] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in KEY_EXT:
            continue
        entry = _classify_private_key(path) if _is_private_key(path) else _classify_cert(path)
        if entry is None:
            continue
        entry.path = str(path.relative_to(root))
        entries.append(entry)
    _flag(entries)
    return entries


def _flag(entries: list[KeyEntry]) -> None:
    now = datetime.now(UTC)
    cert_spki = {e.spki for e in entries if e.kind == "certificate" and e.spki}
    key_spki = {e.spki for e in entries if e.kind == "private-key" and e.spki}
    for e in entries:
        # `bits` holds an RSA modulus and nothing else (WEAK_BITS), so this threshold says "this RSA key
        # is breakable" and cannot say it about a curve or a DSA prime.
        if e.bits is not None and e.bits <= WEAK_BITS:
            e.flags.append(f"weak-key-{e.bits}bit")
        # An algorithm with no threshold here is neither strong nor weak here, and saying nothing would
        # read as the first. Say which one it is instead (#144). Certificates are left alone: #143 owns
        # how they are classified and already leaves their `bits` as an RSA modulus or None.
        if e.kind == "private-key" and e.algorithm not in DECIDED_ALGORITHMS:
            reason = (e.algorithm or "unknown-algorithm").lower()
            e.flags.append(f"strength-undecided-{reason}")
        if e.self_signed:
            e.flags.append("self-signed")
        if e.not_after:
            with_tz = _parse_date(e.not_after)
            if with_tz is not None:
                e.expired = with_tz < now
                if e.expired:
                    e.flags.append("expired")
        if e.kind == "private-key" and e.spki and e.spki in cert_spki:
            e.flags.append("private-key-for-a-shipped-cert")
        if e.kind == "certificate" and e.spki and e.spki in key_spki:
            e.flags.append("private-key-present")


def _parse_date(text: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


@keys_app.command("scan")
def scan_cmd(
    directory: Path = typer.Argument(..., exists=True, file_okay=False, help="extracted firmware filesystem tree"),
    as_json: bool = typer.Option(False, "--json", help="print the inventory as JSON"),
    out: Path = typer.Option(None, "--out", file_okay=False, help="copy the private keys here for analyze --keys-from"),
) -> None:
    """Inventory the key material in an extracted firmware tree and flag the dangerous parts."""
    if openssl_path() is None:
        console.print("[red]keys scan needs openssl on PATH[/red]")
        raise typer.Exit(code=2)
    entries = scan(directory)
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        copied = 0
        for e in entries:
            if e.kind == "private-key" and not e.encrypted:
                (out / f"key{copied:03d}.pem").write_bytes((directory / e.path).read_bytes())
                copied += 1
        console.print(f"wrote {copied} private key(s) to {out} (use: pcap-doctor analyze <pcap> --keys-from {out})")
    if as_json:
        typer.echo(jsonlib.dumps({"root": str(directory), "entries": [asdict(e) for e in entries]}, indent=2))
        return
    keys = [e for e in entries if e.kind == "private-key"]
    certs = [e for e in entries if e.kind == "certificate"]
    risky = sum(1 for e in entries if e.flags)
    console.print(f"[bold]{directory}[/bold]: {len(keys)} private key(s), {len(certs)} certificate(s), {risky} flagged")
    table = Table(title="key material")
    for col in ("path", "kind", "type", "bits", "CN", "SPKI", "flags"):
        table.add_column(col, overflow="fold")
    for e in entries:
        table.add_row(e.path, e.kind, e.algorithm or "-", str(e.bits or "-"), e.common_name or "-",
                      e.spki or "-", ", ".join(e.flags) or "-")
    console.print(table)
    console.print("[dim]Feed the private keys to a capture: pcap-doctor keys scan <dir> --out keys.d && "
                  "pcap-doctor analyze <pcap> --keys-from keys.d[/dim]")


def register(app: typer.Typer) -> None:
    app.add_typer(keys_app, name="keys")
