"""`keys scan` inventories key material in an extracted firmware tree and flags the dangerous parts (#117)."""

from __future__ import annotations

import json
import subprocess

import pytest

import pcapforensics.cli.keys as keys
from pcapforensics.certificates import openssl_path
from pcapforensics.cli import app
from pcapforensics.cli.keys import scan

needs_openssl = pytest.mark.skipif(openssl_path() is None, reason="needs openssl")


def _make_key_and_cert(dir_path, name, bits, *, self_signed=True):
    key = dir_path / f"{name}.key"
    cert = dir_path / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-nodes", "-days", "3650",
                    "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True)
    return key, cert


def _make_cert(dir_path, name, spec, extra=()):
    """A self-signed certificate whose public key openssl generates from ``spec``."""
    cert = dir_path / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", *spec, "-nodes", "-days", "3650",
                    "-subj", f"/CN={name}", "-keyout", str(dir_path / f"{name}.key"),
                    "-out", str(cert), *extra], capture_output=True, check=True)
    return cert


@needs_openssl
def test_scan_classifies_and_flags(tmp_path):
    fw = tmp_path / "fs"
    (fw / "etc").mkdir(parents=True)
    _make_key_and_cert(fw / "etc", "weakca", 512)          # weak + we hold its key
    _make_key_and_cert(fw / "etc", "device", 2048)         # normal
    entries = scan(fw)
    by = {e.path.rsplit("/", 1)[-1]: e for e in entries}
    assert by["weakca.key"].kind == "private-key" and by["weakca.key"].bits == 512
    assert "weak-key-512bit" in by["weakca.key"].flags
    assert "private-key-for-a-shipped-cert" in by["weakca.key"].flags  # SPKI matches weakca.crt
    assert "private-key-present" in by["weakca.crt"].flags
    assert by["device.key"].bits == 2048 and not any("weak" in f for f in by["device.key"].flags)
    # private-key bytes never surface in an entry
    assert all("PRIVATE KEY" not in json.dumps(e.__dict__) for e in entries)


@needs_openssl
def test_cli_json_and_out_dir(cli_runner, tmp_path):
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_key_and_cert(fw, "srv", 1024)
    result = cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["root"].endswith("fs") and any("weak-key-1024bit" in e["flags"] for e in data["entries"])
    assert "PRIVATE KEY" not in result.output  # no key bytes in the JSON

    out = tmp_path / "keys.d"
    assert cli_runner.invoke(app, ["keys", "scan", str(fw), "--out", str(out)]).exit_code == 0
    written = list(out.glob("*.pem"))
    assert len(written) == 1 and "PRIVATE KEY" in written[0].read_text()  # normalized for --keys-from


def test_scan_needs_a_directory(cli_runner, tmp_path):
    assert cli_runner.invoke(app, ["keys", "scan", str(tmp_path / "nope")]).exit_code == 2


# --- #143: a certificate's key size is readable, and is an RSA modulus size and nothing else ---


@needs_openssl
def test_shipped_certificate_key_size_is_reported_and_flagged_weak(tmp_path):
    """A certificate ships no key file, so its key size has to come out of the certificate itself.

    768-bit RSA has been factored since 2010; reporting such a certificate as only
    "private-key-present" hides that its key is breakable (#143).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_cert(fw, "ca768", ["rsa:768"])
    _make_cert(fw, "ca2048", ["rsa:2048"])
    by = {e.path: e for e in scan(fw) if e.kind == "certificate"}
    assert by["ca768.crt"].bits == 768
    assert "weak-key-768bit" in by["ca768.crt"].flags
    assert by["ca2048.crt"].bits == 2048
    assert not any(f.startswith("weak-key-") for f in by["ca2048.crt"].flags)


@needs_openssl
def test_curve_certificates_are_not_flagged_weak(tmp_path):
    """openssl prints ``Public-Key: (256 bit)`` for a P-256 key too, and 256 is not a weak RSA key.

    WEAK_BITS is an RSA modulus threshold, so reading that number into ``bits`` would flag every
    NIST-recommended curve as a breakable key (#143). What a curve size should mean is #144.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_cert(fw, "p256", ["ec"], ["-pkeyopt", "ec_paramgen_curve:P-256"])
    _make_cert(fw, "p384", ["ec"], ["-pkeyopt", "ec_paramgen_curve:P-384"])
    certs = {e.path: e for e in scan(fw) if e.kind == "certificate"}
    assert set(certs) == {"p256.crt", "p384.crt"}
    for e in certs.values():
        assert e.bits is None
        assert not any(f.startswith("weak-key-") for f in e.flags)


_X509_TEXT = """Certificate:
    Data:
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=gate
        Validity
            Not After: Dec 31 23:59:59 2099 GMT
        Subject: CN=gate
        Subject Public Key Info:
            Public Key Algorithm: {alg}
{size}
"""


def _classify_canned_cert(tmp_path, monkeypatch, alg, size):
    """Classify one certificate from a canned ``openssl x509 -text`` dump.

    Not every key here is generable wherever the tests run -- OpenSSL 3 refuses to generate a DSA
    key below 2048 bits -- so the text openssl would print is handed over directly. The contract
    under test is per algorithm: which ``bits`` value, and which weak-key flag.
    """
    fw = tmp_path / "fs"
    fw.mkdir(exist_ok=True)
    (fw / "gate.pem").write_text("-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n")
    text = _X509_TEXT.format(alg=alg, size=size).encode()

    def fake_ossl(args, data=None):
        if "-text" in args:
            return 0, text
        if "-pubkey" in args:
            return 0, b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"
        if "-pubin" in args:
            return 0, b"\x30\x03\x02\x01\x00"
        return 0, b"subject=CN=gate\nissuer=CN=gate\nnotAfter=Dec 31 23:59:59 2099 GMT\n"

    monkeypatch.setattr(keys, "_ossl", fake_ossl)
    (entry,) = scan(fw)
    return entry


@pytest.mark.parametrize(
    ("alg", "size", "expected_bits", "expected_weak_flag"),
    [
        # RSA: a real modulus, and the only kind WEAK_BITS is a threshold for.
        ("rsaEncryption", "                Public-Key: (768 bit)", 768, "weak-key-768bit"),
        ("rsassaPss", "                Public-Key: (1024 bit)", 1024, "weak-key-1024bit"),
        ("rsaEncryption", "                Public-Key: (2048 bit)", 2048, None),
        # Not RSA: openssl prints the same line, but the number is a curve or prime size.
        ("id-ecPublicKey", "                Public-Key: (256 bit)", None, None),
        ("id-ecPublicKey", "                Public-Key: (384 bit)", None, None),
        ("dsaEncryption", "                Public-Key: (1024 bit)", None, None),
        ("dsaEncryption", "                Public-Key: (2048 bit)", None, None),
        # No size at all: EdDSA.
        ("ED25519", "                ED25519 Public-Key:", None, None),
        ("ED448", "                ED448 Public-Key:", None, None),
    ],
)
def test_only_an_rsa_key_size_is_read_and_flagged(tmp_path, monkeypatch, alg, size, expected_bits, expected_weak_flag):
    """``bits`` is an RSA modulus size; every other algorithm reports None and is never flagged (#143)."""
    e = _classify_canned_cert(tmp_path, monkeypatch, alg, size)
    assert e.kind == "certificate"
    assert e.bits == expected_bits
    weak = [f for f in e.flags if f.startswith("weak-key-")]
    assert weak == ([expected_weak_flag] if expected_weak_flag else [])


@needs_openssl
def test_certificate_key_size_openssl_cannot_read_is_not_guessed(tmp_path, monkeypatch):
    """A key size we failed to read is not a weak key: None, and no weak-key flag (#143)."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_cert(fw, "ca", ["rsa:2048"])
    real = keys._ossl
    monkeypatch.setattr(keys, "_ossl", lambda args, data=None: (1, b"") if "-text" in args else real(args, data))
    (entry,) = [e for e in scan(fw) if e.kind == "certificate"]
    assert entry.bits is None
    assert not any(f.startswith("weak-key-") for f in entry.flags)
    # the rest of the certificate is still classified
    assert entry.common_name == "ca"
    assert entry.self_signed is True


def test_without_openssl_the_scan_reports_it_instead_of_guessing(cli_runner, tmp_path, monkeypatch):
    """No openssl means no key size, and the command says so instead of inventing one (#143)."""
    fw = tmp_path / "fs"
    fw.mkdir()
    (fw / "thing.crt").write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setattr(keys, "openssl_path", lambda: None)
    assert cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"]).exit_code == 2
    assert scan(fw) == []  # a certificate we cannot read is reported as nothing, not as a weak key

# --- #144: key strength is judged per algorithm; `bits` is an RSA modulus and nothing else ---


def _gen_key(fw, name, *args):
    """Write a private key openssl can generate here; skip where it cannot."""
    path = fw / f"{name}.key"
    r = subprocess.run(["openssl", "genpkey", "-out", str(path), *args], capture_output=True)
    if r.returncode != 0:
        pytest.skip(f"this openssl cannot generate {name}: {r.stderr.decode()[:120]}")
    return path


@needs_openssl
@pytest.mark.parametrize(
    ("name", "curve"),
    [("p256", "P-256"), ("p384", "P-384"), ("bp256", "brainpoolP256r1")],
)
def test_elliptic_curve_key_is_not_a_weak_key(tmp_path, name, curve):
    """openssl prints `Private-Key: (256 bit)` for a P-256 key, and 256 is not a weak RSA modulus.

    P-256 is roughly RSA-3072 equivalent, so raising weak-key-256bit on a NIST-recommended curve tells
    an analyst their key is breakable when it is not (#144).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, name, "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curve}")
    (e,) = scan(fw)
    assert e.algorithm == "EC"
    assert e.bits is None  # a curve size is not an RSA modulus, so it never reaches WEAK_BITS
    assert not any(f.startswith("weak-key-") for f in e.flags)


@needs_openssl
@pytest.mark.parametrize("bits", [768, 1024, 2048])
def test_rsa_key_keeps_its_weak_key_flag(tmp_path, bits):
    """RSA is unchanged by #144: at or below 1024 is breakable, above it is not."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, f"rsa{bits}", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}")
    (e,) = scan(fw)
    assert e.algorithm == "RSA"
    assert e.bits == bits
    weak = [f for f in e.flags if f.startswith("weak-key-")]
    assert weak == ([f"weak-key-{bits}bit"] if bits <= 1024 else [])


@needs_openssl
@pytest.mark.parametrize("pbits", [1024, 2048])
def test_dsa_key_is_undecided_and_never_weak(tmp_path, pbits):
    """A DSA prime size is not comparable with an RSA modulus, so it must not reach WEAK_BITS.

    A 1024-bit DSA key is the case a naive fix gets wrong: the number is <= 1024, so handing it to
    the RSA threshold raises weak-key-1024bit on a key type the project has never had a rule for.
    DSA is reported undecided instead — neither strong nor weak, and saying which (#144).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    params = tmp_path / f"dsa{pbits}-params.pem"  # outside fw: a params file is not scanned
    made = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DSA",
                           "-pkeyopt", f"pbits:{pbits}", "-out", str(params)], capture_output=True)
    if made.returncode != 0:
        pytest.skip(f"this openssl cannot generate a {pbits}-bit DSA key: {made.stderr.decode()[:120]}")
    _gen_key(fw, f"dsa{pbits}", "-paramfile", str(params))
    (e,) = scan(fw)
    assert e.algorithm == "DSA"
    assert e.bits is None  # a DSA prime size is not an RSA modulus
    assert not any(f.startswith("weak-key-") for f in e.flags)
    assert "strength-undecided-dsa" in e.flags


_PKEY_TEXT = {
    "rsa": "Private-Key: (1024 bit, 2 primes)\nmodulus:\n    00:ab\npublicExponent: 65537 (0x10001)\n",
    "ec": "Private-Key: (256 bit)\npriv:\n    ab:cd\nASN1 OID: prime256v1\nNIST CURVE: P-256\n",
    "dsa": "Private-Key: (1024 bit)\npriv:\n    ab:cd\nP:   \n    00:e1\nQ:   \n    00:9e\nG:   \n    68:48\n",
    "ed25519": "ED25519 Private-Key:\npriv:\n    7e:ff\n",
    "ed448": "ED448 Private-Key:\npriv:\n    57:da\n",
    "unknown": "Some-Future-Key: (512 bit)\npriv:\n    ab:cd\n",
}


@pytest.mark.parametrize(
    ("dump", "algorithm", "bits"),
    [
        # Only RSA gets a number back, because only an RSA modulus is what WEAK_BITS thresholds.
        ("rsa", "RSA", 1024),
        ("ec", "EC", None),
        ("dsa", "DSA", None),
        ("ed25519", "ED25519", None),
        ("ed448", "ED448", None),
        # Not recognised is not RSA: guessing "RSA" would call a 512-bit strong key breakable.
        ("unknown", None, None),
    ],
)
def test_only_an_rsa_modulus_is_read_out_of_a_private_key(dump, algorithm, bits):
    assert keys._read_key_text(_PKEY_TEXT[dump]) == (algorithm, bits)


@needs_openssl
def test_fixed_curve_eddsa_key_is_decided_and_carries_no_undecided_note(tmp_path):
    """Ed25519 has one size by definition (RFC 8032): there is no threshold to apply, nothing to undecide."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, "ed25519", "-algorithm", "ED25519")
    (e,) = scan(fw)
    assert e.algorithm == "ED25519"
    assert e.bits is None
    assert e.flags == []


def test_a_key_type_we_cannot_read_is_reported_undecided(tmp_path, monkeypatch):
    """An unplaceable key is neither strong nor weak: it says so, rather than passing in silence (#144)."""
    fw = tmp_path / "fs"
    fw.mkdir()
    (fw / "thing.key").write_text("-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n")

    def fake_ossl(args, data=None):
        return (0, _PKEY_TEXT["unknown"].encode()) if "-text" in args else (1, b"")

    monkeypatch.setattr(keys, "_ossl", fake_ossl)
    (e,) = scan(fw)
    assert e.bits is None
    assert e.flags == ["strength-undecided-unknown-algorithm"]


# --- #149: a certificate reports its algorithm, in the one vocabulary the private-key path uses ---


def _make_alg_cert(fw, name, spec, extra=()):
    """A self-signed certificate of one key family, skipping where this openssl cannot generate one.

    Which families are generable depends on the openssl build, so a family that cannot be made here is
    skipped rather than dropped. The per-family contract does not actually depend on generating
    anything: `_classify_canned_cert` above covers every family on every build, from the dump openssl
    would print (#149).
    """
    try:
        return _make_cert(fw, name, spec, extra)
    except subprocess.CalledProcessError as exc:  # pragma: no cover - depends on the local openssl
        pytest.skip(f"this openssl cannot make a {name} certificate: {exc.stderr.decode()[:120]}")


def _make_dsa_cert(fw, name, pbits):
    """A self-signed DSA certificate; skip where this openssl will not generate DSA parameters."""
    params = fw.parent / f"{name}-params.pem"  # outside fw: a params file is not scanned
    made = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DSA",
                          "-pkeyopt", f"pbits:{pbits}", "-pkeyopt", "qbits:256",
                          "-out", str(params)], capture_output=True)
    if made.returncode != 0:
        pytest.skip(f"this openssl cannot generate a {pbits}-bit DSA key: {made.stderr.decode()[:120]}")
    key = fw / f"{name}.key"
    made = subprocess.run(["openssl", "genpkey", "-paramfile", str(params), "-out", str(key)],
                          capture_output=True)
    if made.returncode != 0:
        pytest.skip(f"this openssl cannot generate a {pbits}-bit DSA key: {made.stderr.decode()[:120]}")
    cert = fw / f"{name}.crt"
    made = subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(key), "-days", "3650",
                           "-subj", f"/CN={name}", "-out", str(cert)], capture_output=True)
    if made.returncode != 0:  # pragma: no cover - depends on the local openssl
        pytest.skip(f"this openssl cannot sign a DSA certificate: {made.stderr.decode()[:120]}")
    return cert


@needs_openssl
@pytest.mark.parametrize(
    ("name", "spec"),
    [
        ("rsa", ["rsa:2048"]),
        ("ec", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]),
        ("ed25519", ["ed25519"]),
        ("ed448", ["ed448"]),
    ],
)
def test_certificate_reports_its_algorithm(tmp_path, name, spec):
    """A certificate ships no key file, so its algorithm has to come out of the certificate itself.

    openssl puts it on a "Public Key Algorithm:" line and :func:`parse_openssl_text` already reads it
    into `CertFacts.key_algorithm`; the scan used that value to gate `bits` and then dropped it, so
    the type column showed `-` for every certificate and the analyst could not see why one was or was
    not flagged (#149).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, name, spec)
    (cert,) = [e for e in scan(fw) if e.kind == "certificate"]
    assert cert.algorithm == {"rsa": "RSA", "ec": "EC", "ed25519": "ED25519", "ed448": "ED448"}[name]


@needs_openssl
def test_dsa_certificate_reports_its_algorithm(tmp_path):
    """DSA is a family of its own here, so it gets a real certificate rather than a canned dump."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_dsa_cert(fw, "dsa", 2048)
    (cert,) = [e for e in scan(fw) if e.kind == "certificate"]
    assert cert.algorithm == "DSA"
    assert cert.bits is None  # a DSA prime size is not an RSA modulus (#143)


@needs_openssl
@pytest.mark.parametrize(
    ("name", "spec"),
    [
        ("rsa", ["rsa:2048"]),
        ("ec", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]),
        ("ed25519", ["ed25519"]),
        ("ed448", ["ed448"]),
    ],
)
def test_a_certificate_and_its_private_key_spell_one_algorithm_one_way(tmp_path, name, spec):
    """One table gets one vocabulary: RSA cannot appear as both `RSA` and `rsaEncryption`.

    openssl calls the same algorithm differently depending on the dump -- a key says `RSA`, a
    certificate says `rsaEncryption` -- and the scan puts private keys and certificates in one
    table, so exactly one of those spellings may survive. Both paths go through one helper (#149).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, name, spec)  # writes the matching private key beside the certificate
    by_kind = {e.kind: e for e in scan(fw)}
    assert by_kind["certificate"].algorithm is not None
    assert by_kind["certificate"].algorithm == by_kind["private-key"].algorithm


@needs_openssl
def test_no_openssl_spelling_reaches_the_table(tmp_path):
    """Every value in the table is one of our names, whichever dump openssl produced it from.

    This is the property that fails if the certificate path is ever wired back to openssl's own names
    without passing through the shared helper (#149).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    for name, spec in (("rsa", ["rsa:2048"]),
                       ("ec", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]),
                       ("ed25519", ["ed25519"]),
                       ("ed448", ["ed448"])):
        _make_alg_cert(fw, name, spec)
    reported = {e.algorithm for e in scan(fw)}
    assert reported == {"RSA", "EC", "ED25519", "ED448"}
    assert reported <= set(keys.DECIDED_ALGORITHMS) | {"EC"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # What openssl writes after "Public Key Algorithm:" on a certificate ...
        ("rsaEncryption", "RSA"),
        ("rsassaPss", "RSA"),
        ("id-ecPublicKey", "EC"),
        ("dsaEncryption", "DSA"),
        # ... which openssl has also spelled with an OID prefix and in another case: 3.6 prints
        # "ED25519" where older releases print "id-Ed25519".
        ("ED25519", "ED25519"),
        ("id-Ed25519", "ED25519"),
        ("ED448", "ED448"),
        ("id-Ed448", "ED448"),
        # And the tokens a private-key dump is identified by, which must survive unchanged.
        ("RSA", "RSA"),
        ("EC", "EC"),
        ("DSA", "DSA"),
        ("ED25519", "ED25519"),
        ("ED448", "ED448"),
        # A name we hold no word for is not guessed at: it is not RSA, so it acquires no modulus size.
        ("dhpublicnumber", None),
        ("X25519", None),
        # Nothing read is nothing named (AGENTS.md section 4).
        ("", None),
        (None, None),
    ],
)
def test_one_helper_names_every_algorithm_spelling(raw, expected):
    assert keys._algorithm_name(raw) == expected


@pytest.mark.parametrize("alg", ["dhpublicnumber", "X25519"])
def test_a_certificate_algorithm_outside_the_vocabulary_is_reported_as_none(tmp_path, monkeypatch, alg):
    """openssl naming a key type we hold no word for is not a licence to invent one for it (#149).

    The alternative -- passing openssl's own string through -- is the two-vocabularies bug: the table
    would read `RSA` on one row and `rsaEncryption` on the next. So an unnamed algorithm is
    reported the way an unreadable one is, and #148 owns the surface that says so out loud.
    """
    e = _classify_canned_cert(tmp_path, monkeypatch, alg, "                Public-Key: (2048 bit)")
    assert e.algorithm is None
    assert e.bits is None  # not named RSA, so the number is not read as an RSA modulus
    assert not any(f.startswith("weak-key-") for f in e.flags)
    assert e.common_name == "gate"  # the rest of the certificate is still classified


def test_a_certificate_algorithm_openssl_cannot_read_is_not_guessed(tmp_path, monkeypatch):
    """A key we failed to read is named None, not filled in from whatever the size line hints at (#149)."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, "ca", ["rsa:2048"])
    real = keys._ossl
    monkeypatch.setattr(keys, "_ossl", lambda args, data=None: (1, b"") if "-text" in args else real(args, data))
    (entry,) = [e for e in scan(fw) if e.kind == "certificate"]
    assert entry.algorithm is None
    assert entry.bits is None
    assert not any(f.startswith("weak-key-") for f in entry.flags)
    assert entry.common_name == "ca"  # everything else about it is still read


@needs_openssl
def test_reporting_a_certificate_algorithm_changes_no_certificate_flag(tmp_path):
    """Reading the algorithm is a reporting fix, not a judgement one: #143 and #155 own the flags.

    `bits` is an RSA modulus and only an RSA modulus, so this must not give a certificate a
    `weak-key-*` flag it did not already have, and it must not hand a certificate the private-key
    path's `strength-undecided-*` note -- that one is keyed on `algorithm`, and would otherwise
    start appearing on every EC and DSA certificate the moment this field became populated (#149).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, "ca768", ["rsa:768"])  # still flagged weak, exactly as #143 left it
    _make_alg_cert(fw, "p256", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"])
    by = {e.path: e for e in scan(fw) if e.kind == "certificate"}
    assert "weak-key-768bit" in by["ca768.crt"].flags
    assert by["p256.crt"].algorithm == "EC"
    for e in by.values():
        assert not any(f.startswith("strength-undecided-") for f in e.flags)
    assert not any(f.startswith("weak-key-") for f in by["p256.crt"].flags)


@needs_openssl
def test_the_certificate_algorithm_reaches_the_json_output(cli_runner, tmp_path):
    """The field is on the entry, not only on the rendered table -- a machine reading --json gets it too."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, "ca", ["rsa:2048"])
    result = cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"])
    assert result.exit_code == 0
    certs = [e for e in json.loads(result.output)["entries"] if e["kind"] == "certificate"]
    assert [c["algorithm"] for c in certs] == ["RSA"]
