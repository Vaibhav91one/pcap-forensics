"""``keys scan``: inventory the key material in an already-extracted firmware tree (issue #117, Phase B).

Authorized white-box testing. The input is a filesystem tree (e.g. an unpacked firmware image); pcap-doctor
never unpacks or executes firmware. It classifies every PEM private key and certificate, flags the dangerous
ones (weak key, self-signed, expired, and — critically — a private key whose public half matches a shipped
certificate, meaning the operator *holds the key for that cert*), and can normalise the private keys into a
directory that ``analyze --keys-from`` consumes to decrypt a capture.

Findings and non-answers are kept apart, because they are not the same kind of statement. ``KeyEntry.flags``
is what is wrong with the key; ``KeyEntry.undecided`` is what this command could not decide about it. An entry
may be in both — a DSA key that ships beside its own certificate is both — and counting ignorance as a
finding reports a key the project has no rule for as a defect and tells a reader to act on nothing (#144,
#148). A key this command *can* judge belongs in neither column: that is the "checked, fine" answer, and an
empty cell means it rather than "not looked at" (#162).

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
from ..data_ciphers import MIN_EC_CURVE_BITS
from ..prompts import clean
from ._console import console

keys_app = typer.Typer(help="Inspect key material in an extracted firmware tree.", no_args_is_help=True)

KEY_EXT = (".pem", ".key", ".der", ".crt", ".cer")
WEAK_BITS = 1024  # RSA <= 1024 bits is breakable; flag it

# `bits` is an RSA modulus size, and only an RSA modulus size: WEAK_BITS is an RSA threshold. openssl
# reports every public key type through the same "Public-Key: (N bit)" line, but the number means
# something different for each — a curve size for EC, a prime size for DSA — so the algorithm is what
# decides whether the number may be compared against WEAK_BITS at all. See _read_cert_key for the
# certificate path and _read_key_text for the private-key path: both set `bits` for RSA alone, so the
# one comparison in _flag is an RSA statement by construction rather than by a second guess at the type.

# An EC curve size is a second quantity with a second threshold, so it gets its own field
# (`KeyEntry.curve_bits`) rather than being folded into `bits`: one field holding two meanings is
# exactly what #143 removed, and a `bits <= WEAK_BITS` left unguarded is a P-256 key reported as weak.
#
# The threshold itself is not written here. MIN_EC_CURVE_BITS is imported from `data_ciphers`, where
# #151 moved the numbers out of `detectors/tls_cipher.py` so that a second consumer could read the same
# policy instead of rediscovering it (#162). RFC 8422 section 5.1.1 deprecates NamedCurve 1-22 for TLS,
# which is every curve below 256 bits, so the floor is the minimum curve TLS still permits.
#
# The policy draws one more line inside that range: below DEPRECATED_EC_CURVE_BITS (224) a curve is
# treated as broken, and between the two constants it is deprecated-for-TLS rather than a break. That
# distinction is a ranking, and this command has no severity to rank with — one flag says `weak-key-<n>bit`
# — so both bands read the same way here. `weak_key_verdict`, which does have severities, keeps the two
# apart for the capture path; the floor, which is the part that decides whether a key is reported at all,
# is the part shared.

# One vocabulary for `KeyEntry.algorithm`, whichever dump produced the value (#149). openssl names the
# same fact differently depending on where it read it: a private key says "RSA"/"EC"/"DSA"/"ED25519"/
# "ED448", a certificate says "rsaEncryption"/"id-ecPublicKey"/"dsaEncryption". The scan prints both
# kinds of entry in one table, so one of those spellings has to go. We keep the private-key spelling: it
# is the one `KeyEntry.algorithm` is documented in, the one `DECIDED_ALGORITHMS` and the
# `strength-undecided-*` flag are written against, and the shorter one to read.
#
# Matched case-insensitively, because openssl is not self-consistent about the Ed names either: 3.6
# prints "ED25519" where older releases print "id-Ed25519", so both are listed rather than one of them
# being assumed (#149). A name absent from this table is not guessed at — see _algorithm_name.
_ALGORITHM_NAMES = {
    "rsa": "RSA",
    "rsaencryption": "RSA",
    "rsassapss": "RSA",
    "ec": "EC",
    "id-ecpublickey": "EC",
    "dsa": "DSA",
    "dsaencryption": "DSA",
    "ed25519": "ED25519",
    "id-ed25519": "ED25519",
    "ed448": "ED448",
    "id-ed448": "ED448",
}

# Algorithms whose strength this command can decide. RSA is judged on its modulus against WEAK_BITS, and
# EC on its curve size against MIN_EC_CURVE_BITS, which is the same policy the capture path reads (#162).
# Ed25519 and Ed448 are not parameterised by a secret size at all — RFC 8032 fixes the curve — so there
# is no number to brute-force and no threshold to apply. Everything else (DSA, for which there is still
# no tier, and any key type openssl describes in a way we do not recognise) is reported undecided by
# _flag rather than judged by another algorithm's rule or silently passed over as acceptable
# (AGENTS.md section 4).
#
# Decided is a property of the algorithm, not of the entry: an EC key whose curve size openssl would not
# read is not decidable, and says so in `undecided` as `key-size-unreadable` rather than being judged
# from nothing (#162).
DECIDED_ALGORITHMS = frozenset({"RSA", "EC", "ED25519", "ED448"})

# The note an entry carries when openssl would not parse it at all (#163). A file with a key-ish
# suffix that no longer holds anything we can read is still a file we looked at, and the scan says so
# here rather than dropping the row -- a tree whose only member is unreadable used to report exactly
# what an empty tree reports. It is a `undecided` note and not a flag: we could not read the file,
# which is a fact about this command, not a claim that what the device ships is unsafe (#148).
_UNREADABLE_CERT = "certificate-unreadable"

#: A path in the scan table is read in full by an analyst triaging a firmware image, so it gets the
#: report value limit rather than the prompt's 200-character label limit -- the same number #170 chose
#: for 03-findings.md, and for the same reason. The sanitiser is not re-implemented here.
CAPTURE_VALUE_LIMIT = 400


def _capture_text(value: str) -> str:
    """A firmware-chosen file name on its way into the `keys scan` table (#169).

    Whoever built the firmware chooses every name in the unpacked tree, and the path reached the
    table raw: \x1b[31m coloured a row and \x1b]0;title=pwned retitled the terminal an analyst
    was reading. A hostile image could therefore lie about the very inventory meant to show what it
    ships.

    This is the same call #170 made in the Markdown renderer -- one more caller of the sanitiser the
    JSON envelope and every prompt path already use, not a second sanitiser and not a second copy of
    the control-character regex.

    Applied to the *rendered cell* only, never in :func:`scan`. By the time a row is built,
    ``KEY_EXT`` has already matched the suffix and the walk has already produced the entry, so
    sanitising here cannot change which files were scanned -- only how the one that was is shown.
    (It is also why the hostile names in the tests end in ``.pem``: a name without a recognised
    suffix is skipped by the walk, prints nothing, and would make any "no escapes here" assertion
    pass for the wrong reason.)

    Unlike #170's helper this one does not escape ``|``: a rich table is delimited by box drawing,
    not by pipes, and rewriting a pipe inside a file name would corrupt a name that is merely
    ordinary rather than hostile.
    """
    return clean(value, limit=CAPTURE_VALUE_LIMIT)


@dataclass
class KeyEntry:
    path: str  # relative to the scanned root
    kind: str  # "private-key" or "certificate"
    # RSA / EC / DSA / ED25519 / ED448, or None if unreadable or a type this module does not name
    algorithm: str | None = None
    bits: int | None = None  # an RSA modulus size, and only ever one — see WEAK_BITS
    # An EC curve size, and only ever one — see MIN_EC_CURVE_BITS. Kept out of `bits` on purpose: that
    # field is an RSA modulus and one threshold, and a curve is neither (#143, #162).
    curve_bits: int | None = None
    encrypted: bool = False
    common_name: str | None = None
    self_signed: bool | None = None
    not_after: str | None = None
    expired: bool | None = None
    spki: str | None = None  # sha256(DER public key)[:16] — non-secret
    flags: list[str] = field(default_factory=list)
    # What this command could not determine about this entry, kept apart from `flags` because it is
    # not the same kind of statement. A flag is a claim about the key: this modulus is breakable, you
    # hold the key for this certificate. An entry in `undecided` is a claim about *us*: we have no
    # rule covering this algorithm, or openssl would not read a size we asked for. Counting the
    # second as the first reports a healthy P-256 key as a defect, and gives `I do not know` the same
    # weight as `this is dangerous` (AGENTS.md section 4). #144 shipped the note as a flag and
    # #148 gave it a channel of its own.
    #
    # The vocabulary is unchanged from #144 -- `strength-undecided-<algorithm>` -- so a consumer of
    # --json reads the same words as before, out of a different field.
    undecided: list[str] = field(default_factory=list)


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


def _algorithm_name(raw: str | None) -> str | None:
    """openssl's name for a public-key algorithm -> this module's name for it (#149).

    The one place an algorithm becomes a `KeyEntry.algorithm` value, so the certificate path and the
    private-key path cannot drift into two vocabularies for one table. It reads no key and no
    certificate; it is a pure mapping, and idempotent over both input shapes, which is what lets
    `_read_key_text` keep naming the types it identifies while the spelling itself is chosen here.

    An input that is absent, or that names a key type this table does not hold, comes back `None`
    rather than a best guess — the same answer a private-key dump matching none of `_read_key_text`'s
    markers already gets. A certificate naming a key type we hold no word for is still a certificate we
    read; we just do not have the word for it, and #148 owns the surface that says so out loud
    (AGENTS.md section 4).
    """
    return _ALGORITHM_NAMES.get(raw.lower()) if raw else None


def _read_key_text(text: str) -> tuple[str | None, int | None, int | None]:
    """``(algorithm, RSA modulus size, EC curve size)`` read out of an ``openssl pkey -text`` dump (#144).

    openssl prints the same ``Private-Key: (N bit)`` line for every key type, and N is a different
    quantity in each: a modulus for RSA, a curve size for EC, a prime size for DSA. The two sizes come
    back in two different slots because they are answered by two different thresholds — handing the curve
    size of a NIST-recommended P-256 key to an RSA breakability threshold reports a key roughly as strong
    as RSA-3072 as weak, and handing an RSA modulus to a curve floor reports a strong key as deprecated.
    Only the slot whose threshold applies is filled (#143, #162).

    Each algorithm is recognised from a marker openssl prints for that algorithm alone, and a key
    matching none of them comes back as ``None`` rather than being assumed to be RSA: an unplaceable
    key is then reported undecided by ``_flag``, which is honest, where a default of "RSA" would call
    a strong key breakable (AGENTS.md section 4). A DSA prime size is read by neither slot: there is
    still no DSA tier to compare it against (#155), so it is left undecided rather than measured against
    someone else's floor.
    """
    size = re.search(r"\((\d+)\s*bit", text)  # "Private-Key: (512 bit, 2 primes)"
    modulus = int(size.group(1)) if size else None
    header = text.lstrip().partition("\n")[0]
    if header.startswith(("ED25519", "ED448")):
        return header.partition(" ")[0], None, None  # "ED25519 Private-Key:" — fixed-parameter, no size
    if "ASN1 OID:" in text:  # every EC key: "ASN1 OID: prime256v1", "ASN1 OID: brainpoolP256r1"
        return "EC", None, modulus
    if all(re.search(rf"^{name}:\s*$", text, re.M) for name in ("P", "Q", "G")):  # DSA prints p, q, g
        return "DSA", None, None
    if "modulus:" in text and "publicExponent:" in text:  # RSA alone
        return "RSA", modulus, None
    return None, None, None


def _classify_private_key(path: Path) -> KeyEntry:
    e = KeyEntry(path="", kind="private-key")
    rc, out = _ossl(["pkey", "-in", str(path), "-noout", "-text"])
    if rc != 0:
        rc, out = _ossl(["rsa", "-in", str(path), "-noout", "-text", "-passin", "pass:"])
    if rc != 0:
        e.encrypted = True  # a key we can't read without a passphrase (still: key material is present)
        return e
    raw_algorithm, e.bits, e.curve_bits = _read_key_text(out.decode("latin-1"))
    e.algorithm = _algorithm_name(raw_algorithm)
    rc, pub = _ossl(["pkey", "-in", str(path), "-pubout", "-outform", "DER"])
    if rc != 0:
        rc, pub = _ossl(["rsa", "-in", str(path), "-pubout", "-outform", "DER", "-passin", "pass:"])
    if rc == 0 and pub:
        e.spki = _spki_of_pubkey_der(pub)
    return e


def _classify_cert(path: Path) -> KeyEntry:
    """Classify a certificate, and say so when there is not one to read (#163).

    This used to return ``None`` when openssl would not parse the file, and ``scan`` dropped that, so
    a truncated, encrypted or mislabelled PEM vanished: no row, no flag, no note, and not in the count.
    A tree holding one unreadable certificate then reported exactly what an empty tree reports, and an
    analyst reading "0 certificate(s)" could not tell a clean scan from a skipped file -- which is the
    silent pass AGENTS.md section 4 forbids.

    The decision is to keep the row and mark it. The file had a certificate-ish suffix and was not a
    private key, so it is a certificate we failed to read: an entry with no algorithm, no dates and no
    CN, `flags` empty because there is nothing here to accuse the key of, and
    `KeyEntry.undecided = ["certificate-unreadable"]` because the one true thing we know is that we
    could not read it (#148). The row counts as a certificate so the summary cannot read as clean.
    """
    rc, out = _ossl(["x509", "-in", str(path), "-noout", "-subject", "-issuer", "-enddate", "-nameopt", "RFC2253"])
    if rc != 0:
        return KeyEntry(path="", kind="certificate", undecided=[_UNREADABLE_CERT])
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
    _read_cert_key(e, path)
    return e


def _read_cert_key(e: KeyEntry, path: Path) -> None:
    """Read a shipped certificate's public-key algorithm, and for RSA alone its modulus size (#143, #149).

    A certificate carries no key file to read, so this is where `keys scan` learns what kind of key
    it ships and how big that key is — without it a 768-bit certificate reads as merely
    "private-key-present". openssl reports the kind on a `Public Key Algorithm:` line and the size as
    "Public-Key: (768 bit)", but it prints that same size line for an EC key with the curve size, where
    256 is a *strong* key, and for a DSA key with a prime size. Handing either to `_flag`'s RSA
    threshold is issue #144, so the number is routed to the field whose threshold it answers: an RSA
    modulus to `bits`, a curve size to `curve_bits` (#162), and a DSA prime to neither, because there
    is still no DSA tier (#155). The algorithm is read either way, so the type column can say what the
    key is instead of showing `-` on every row (#149).

    All of these values come out of :func:`parse_openssl_text`, the same parser the capture path
    reads, so this command and the capture cannot end up answering "what algorithm is this", or "how
    big is this key", in two ways.

    A certificate whose algorithm cannot be read keeps `algorithm=None`, and one whose *size* cannot
    be read keeps `bits=None` and `curve_bits=None`: a key we could not read is not a weak key, and
    naming either one would invent a fact the file does not contain (AGENTS.md section 4).
    """
    rc, text = _ossl(["x509", "-in", str(path), "-noout", "-text"])
    if rc != 0:
        return
    facts = parse_openssl_text(text.decode("latin-1"))
    e.algorithm = _algorithm_name(facts.key_algorithm)
    if e.algorithm == "RSA":
        e.bits = facts.public_key_bits
    elif e.algorithm == "EC":
        e.curve_bits = facts.public_key_bits


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
        # Both classifiers answer with an entry now: a file we could not read comes back marked, not
        # as `None` to be dropped here (#163). Nothing on this walk is silently skipped.
        entry = _classify_private_key(path) if _is_private_key(path) else _classify_cert(path)
        entry.path = str(path.relative_to(root))
        entries.append(entry)
    _flag(entries)
    return entries


def _mark_undecided(e: KeyEntry) -> None:
    """Everything about this entry's strength that this command has no verdict for (#148).

    Two reasons, and they are kept apart because a missing size means both of them at once:

    * the algorithm is one that no rule here covers. DSA has no tier in this module — there is
      nothing to compare a prime size against — and an algorithm openssl named in a way
      `_ALGORITHM_NAMES` holds no word for is not assumed to be anything. EC used to belong here too,
      until #162 gave this command the curve policy the capture path already had (#151): a curve is
      now judged against MIN_EC_CURVE_BITS, so `strength-undecided-ec` is no longer a thing this
      command can say.
    * the algorithm is one this command judges on a size, and the size did not come back. For RSA
      that is the modulus in `bits`, for EC the curve size in `curve_bits`; in both cases the number
      *is* readable, so a missing one is us failing rather than the key having no size -- the
      unreadable certificate in #148's own evidence. ED25519 and ED448 are in `DECIDED_ALGORITHMS`
      and are fixed-parameter, so their size is None by design and they are *decided*, which is a
      different answer and gets no note at all.

    Mutates `e.undecided` rather than returning, so an entry may carry more than one reason and
    the caller never has to know how many there are.
    """
    if _UNREADABLE_CERT in e.undecided:
        # We never read a key here, so there is no strength to have a verdict about. Adding the
        # algorithm note as well would give a file we could not open two reasons and neither would be
        # right: its strength is not undecided, it is unknown because there was nothing to read (#163).
        return
    if e.algorithm not in DECIDED_ALGORITHMS:
        reason = (e.algorithm or "unknown-algorithm").lower()
        e.undecided.append(f"strength-undecided-{reason}")
    elif e.algorithm in ("RSA", "EC"):
        # Both are judged on a size, and each keeps it in the slot its own threshold reads (#162);
        # asking the wrong slot would report every key this command cannot size as unreadable.
        size = e.bits if e.algorithm == "RSA" else e.curve_bits
        if size is None:
            e.undecided.append("key-size-unreadable")


def _flag(entries: list[KeyEntry]) -> None:
    now = datetime.now(UTC)
    cert_spki = {e.spki for e in entries if e.kind == "certificate" and e.spki}
    key_spki = {e.spki for e in entries if e.kind == "private-key" and e.spki}
    for e in entries:
        # `bits` holds an RSA modulus and nothing else (WEAK_BITS), so this threshold says "this RSA key
        # is breakable" and cannot say it about a curve or a DSA prime.
        if e.bits is not None and e.bits <= WEAK_BITS:
            e.flags.append(f"weak-key-{e.bits}bit")
        # A curve is judged against the policy #151 wrote down, imported rather than restated, so the
        # same P-192 key is a finding here and `high` in the capture path instead of being an unknown
        # in one and a defect in the other (#162). The flag keeps the `weak-key-<n>bit` shape: below the
        # floor a curve is reported, at or above it there is nothing to say and nothing is said.
        if e.algorithm == "EC" and e.curve_bits is not None and e.curve_bits < MIN_EC_CURVE_BITS:
            e.flags.append(f"weak-key-{e.curve_bits}bit")
        # An algorithm with no threshold here is neither strong nor weak here, and saying nothing would
        # read as the first. Say which one it is instead (#144) -- in a column and a count of its own,
        # because it is a claim about this command rather than about the key (KeyEntry.undecided).
        _mark_undecided(e)
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
    flagged = sum(1 for e in entries if e.flags)
    undecided = sum(1 for e in entries if e.undecided)
    if as_json:
        # The two counts ride along at the top level as well as per entry: a CI gate should be able to
        # read "how many findings" and "how many unknowns" without re-deriving either from the list
        # (#148). Every key already in this payload is unchanged; both are additive.
        typer.echo(jsonlib.dumps({"root": str(directory), "flagged": flagged, "undecided": undecided,
                                  "entries": [asdict(e) for e in entries]}, indent=2))
        return
    keys = [e for e in entries if e.kind == "private-key"]
    certs = [e for e in entries if e.kind == "certificate"]
    console.print(f"[bold]{directory}[/bold]: {len(keys)} private key(s), {len(certs)} certificate(s), "
                  f"{flagged} flagged, {undecided} undecided")
    table = Table(title="key material")
    for col in ("path", "kind", "type", "bits", "CN", "SPKI", "flags", "undecided"):
        table.add_column(col, overflow="fold")
    for e in entries:
        # One "bits" column, both sizes: a column showing `-` next to a `weak-key-192bit` flag would
        # hide the number the flag is about, and an EC row whose verdict is "decided" should show the
        # curve size that decided it (#162).
        #
        # `path` goes through the sanitiser and nothing else does, because it is the one cell here the
        # firmware author chose: every other column is derived by openssl or by this module (#169).
        table.add_row(_capture_text(e.path), e.kind, e.algorithm or "-", str(e.bits or e.curve_bits or "-"),
                      e.common_name or "-", e.spki or "-", ", ".join(e.flags) or "-",
                      ", ".join(e.undecided) or "-")
    console.print(table)
    # "undecided" is what this command could not decide, not something it found wrong: an entry may
    # appear in both counts, and an empty cell means the answer was "checked, fine" rather than
    # "not looked at". Both readings are needed and neither implies the other (#148). Since #163 the
    # column also carries `certificate-unreadable`, so the legend names both things it can mean.
    console.print("[dim]undecided = what this command could not decide: no strength verdict, or a file "
                  "it could not read. Not a finding; flagged and undecided overlap.[/dim]")
    console.print("[dim]Feed the private keys to a capture: pcap-doctor keys scan <dir> --out keys.d && "
                  "pcap-doctor analyze <pcap> --keys-from keys.d[/dim]")


def register(app: typer.Typer) -> None:
    app.add_typer(keys_app, name="keys")
