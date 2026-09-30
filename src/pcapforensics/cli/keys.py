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

from ..certificates import openssl_path
from ._console import console

keys_app = typer.Typer(help="Inspect key material in an extracted firmware tree.", no_args_is_help=True)

KEY_EXT = (".pem", ".key", ".der", ".crt", ".cer")
WEAK_BITS = 1024  # RSA <= 1024 bits is breakable; flag it


@dataclass
class KeyEntry:
    path: str  # relative to the scanned root
    kind: str  # "private-key" or "certificate"
    algorithm: str | None = None  # RSA / EC
    bits: int | None = None
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


def _classify_private_key(path: Path) -> KeyEntry:
    e = KeyEntry(path="", kind="private-key")
    rc, out = _ossl(["pkey", "-in", str(path), "-noout", "-text"])
    if rc != 0:
        rc, out = _ossl(["rsa", "-in", str(path), "-noout", "-text", "-passin", "pass:"])
    if rc != 0:
        e.encrypted = True  # a key we can't read without a passphrase (still: key material is present)
        return e
    text = out.decode("latin-1")
    e.algorithm = "EC" if ("NIST" in text or "ASN1 OID" in text) else "RSA"
    bits = re.search(r"\((\d+)\s*bit", text)  # "Private-Key: (512 bit, 2 primes)"
    e.bits = int(bits.group(1)) if bits else None
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
    return e


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
        if e.bits is not None and e.bits <= WEAK_BITS:
            e.flags.append(f"weak-key-{e.bits}bit")
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
