"""`keys scan` inventories key material in an extracted firmware tree and flags the dangerous parts (#117)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

import pcap_doctor.cli.keys as keys
import pcap_doctor.data_ciphers as data_ciphers
from pcap_doctor.certificates import openssl_path
from pcap_doctor.cli import app
from pcap_doctor.cli.keys import scan
from pcap_doctor.data_ciphers import MIN_EC_CURVE_BITS

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
    """No openssl means no key size, and the command says so instead of inventing one (#143, #163).

    #143 wrote the last line of this test as `scan(fw) == []`, which pinned two things at once: that an
    "unreadable certificate is not a weak key -- still true, and still what the test is for -- and that
    "it is not a row at all, which made a tree holding one broken file report exactly what an empty
    "tree reports. #163 keeps the first half and gives up the second (#148 says a note, not silence).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    (fw / "thing.crt").write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setattr(keys, "openssl_path", lambda: None)
    assert cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"]).exit_code == 2
    (entry,) = scan(fw)  # the file is reported -- as something, rather than as nothing
    assert entry.kind == "certificate"
    assert entry.algorithm is None and entry.bits is None  # nothing invented about it
    assert not any(f.startswith("weak-key-") for f in entry.flags)  # unreadable is not weak (#143)
    assert entry.undecided == ["certificate-unreadable"]  # and unreadable is not silence (#163)

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
    assert "strength-undecided-dsa" in e.undecided  # and is no longer counted as a finding (#148)


_PKEY_TEXT = {
    "rsa": "Private-Key: (1024 bit, 2 primes)\nmodulus:\n    00:ab\npublicExponent: 65537 (0x10001)\n",
    "ec": "Private-Key: (256 bit)\npriv:\n    ab:cd\nASN1 OID: prime256v1\nNIST CURVE: P-256\n",
    "dsa": "Private-Key: (1024 bit)\npriv:\n    ab:cd\nP:   \n    00:e1\nQ:   \n    00:9e\nG:   \n    68:48\n",
    "ed25519": "ED25519 Private-Key:\npriv:\n    7e:ff\n",
    "ed448": "ED448 Private-Key:\npriv:\n    57:da\n",
    "unknown": "Some-Future-Key: (512 bit)\npriv:\n    ab:cd\n",
}


@pytest.mark.parametrize(
    ("dump", "algorithm", "rsa_modulus", "curve_size"),
    [
        # RSA gets a modulus, because an RSA modulus is what WEAK_BITS thresholds.
        ("rsa", "RSA", 1024, None),
        # EC gets a curve size, and only a curve size (#143, #162).
        ("ec", "EC", None, 256),
        # DSA gets neither: a prime size answers no threshold this project has (#155).
        ("dsa", "DSA", None, None),
        ("ed25519", "ED25519", None, None),
        ("ed448", "ED448", None, None),
        # Not recognised is not RSA: guessing "RSA" would call a 512-bit strong key breakable.
        ("unknown", None, None, None),
    ],
)
def test_the_size_read_out_of_a_private_key_is_the_one_its_own_threshold_reads(dump, algorithm, rsa_modulus, curve_size):
    """Two sizes, two slots, and neither number in the other's (#143, #162).

    Handing a P-256 curve size to the RSA breakability threshold calls a key roughly as strong as
    RSA-3072 weak; handing an RSA modulus to the curve floor calls a strong key deprecated. Only the
    slot whose threshold applies is filled, so no comparison downstream can reach the wrong one."""
    assert keys._read_key_text(_PKEY_TEXT[dump]) == (algorithm, rsa_modulus, curve_size)


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
    assert e.flags == []  # not knowing is not a finding (#148)
    assert e.undecided == ["strength-undecided-unknown-algorithm"]  # but it is not silence either (#144)


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


def _make_dsa_key(fw, name, pbits=2048):
    """A DSA private key on its own; skip where this openssl will not generate DSA parameters."""
    params = fw.parent / f"{name}-params.pem"  # outside fw: a params file is not scanned
    made = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DSA",
                           "-pkeyopt", f"pbits:{pbits}", "-pkeyopt", "qbits:256",
                           "-out", str(params)], capture_output=True)
    if made.returncode != 0:
        pytest.skip(f"this openssl cannot generate a {pbits}-bit DSA key: {made.stderr.decode()[:120]}")
    return _gen_key(fw, name, "-paramfile", str(params))


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

    The note itself now reaches certificates, but in `undecided` rather than `flags`, so this
    assertion is what stops that from quietly turning into a certificate flag: see
    `test_a_curve_certificate_is_undecided_exactly_like_its_private_key` (#148).
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

# --- #148: "I could not determine this" is not a finding, and has to be visible as its own thing ---


@needs_openssl
def test_a_healthy_curve_key_is_neither_a_finding_nor_an_unknown(tmp_path):
    """The case #148 exists for, one answer further on than it could reach (#162).

    #144 shipped `strength-undecided-ec` as a flag, which reported the single healthiest entry in a
    tree as a finding and tallied it beside a factored 512-bit key. #148 moved that note into a column
    of its own, where it was still not the same as "checked, fine"; #162 gave this command the curve
    policy the capture path already had, so a P-256 key is now *decided*. Both columns empty is an
    answer -- before, an empty `undecided` meant "we had no rule for this key".
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, "ec-orphan", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    (e,) = scan(fw)
    assert e.algorithm == "EC" and e.curve_bits == 256  # the size the verdict was reached from
    assert e.flags == []  # nothing is wrong with this key
    assert e.undecided == []  # and we did reach a verdict about it


@needs_openssl
def test_a_decided_key_carries_no_undecided_note(tmp_path):
    """The other half of the pair: "fine" is a real, distinct answer and must look like one.

    An Ed25519 key is fixed-parameter (RFC 8032), so there is no threshold to apply and nothing to
    undecide. #148 needs both halves asserted together, because the bug is precisely that these two
    rows used to be told apart only by the absence of a flag.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, "ed25519", "-algorithm", "ED25519")
    (e,) = scan(fw)
    assert e.flags == [] and e.undecided == []  # decided and fine: neither a finding nor an unknown


@needs_openssl
def test_an_undecided_note_does_not_hide_a_real_finding(tmp_path):
    """Separation is by channel, not by deletion: an entry can be both, and stays both.

    DSA is what this case is made of now that a curve is decided (#162): the one key family this
    project still has no strength tier for (#155), so it is a finding and an unknown at once.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_dsa_cert(fw, "dsa", 2048)  # writes a matching key
    by_kind = {e.kind: e for e in scan(fw)}
    key = by_kind["private-key"]
    assert "private-key-for-a-shipped-cert" in key.flags  # the real finding is untouched
    assert key.undecided == ["strength-undecided-dsa"]  # and the unknown is still reported


def _flat(text: str) -> str:
    """One line with runs of whitespace collapsed, so a width-80 rich console cannot fail an assert."""
    return " ".join(text.split())


@needs_openssl
def test_the_summary_counts_flagged_and_undecided_separately(cli_runner, tmp_path):
    """The summary must not add ignorance into the finding count (#148).

    One key this command has no verdict for and one genuinely dangerous pair, so the two numbers
    cannot coincide and a test cannot pass by accident.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_dsa_key(fw, "dsa-orphan")  # no DSA tier exists, so this one is undecided (#155)
    _make_alg_cert(fw, "weak", ["rsa:768"])
    result = cli_runner.invoke(app, ["keys", "scan", str(fw)])
    assert result.exit_code == 0
    summary = _flat(result.output).split("key material")[0]
    assert "2 flagged" in summary  # weak.crt and weak.key only
    assert "1 undecided" in summary  # the DSA key, counted on its own


@needs_openssl
def test_undecided_survives_the_json_output(cli_runner, tmp_path):
    """--json is what CI reads, so the distinction has to survive it or it does not exist (#148)."""
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_dsa_key(fw, "dsa-orphan")  # the one family #162 leaves undecided, so this channel is tested
    result = cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    (entry,) = data["entries"]
    assert entry["undecided"] == ["strength-undecided-dsa"]
    assert entry["flags"] == []  # a machine reading flags must not count this as a defect
    # and the counts are in the JSON too, so a CI gate does not have to re-derive them
    assert data["undecided"] == 1 and data["flagged"] == 0


@needs_openssl
def test_a_certificate_whose_key_size_cannot_be_read_says_so(tmp_path, monkeypatch):
    """#148's own motivating evidence: a certificate openssl could not size.

    `bits=None` here means "we did not read it". For RSA that is ignorance and has to say so; for
    a curve it is "there is no RSA modulus here" and must not. Reporting both as an empty cell is
    what made the original bug report possible (#143 raised the flag, #148 gives it a voice).
    """
    # openssl names the algorithm and prints the modulus size on one dump, and the two are read
    # independently, so "this is an RSA key" and "here is how many bits" can disagree. The canned
    # dump is the disagreement itself: rsaEncryption, and no size line for parse_openssl_text to read.
    e = _classify_canned_cert(tmp_path, monkeypatch, "rsaEncryption", "                (no size here)")
    assert e.algorithm == "RSA" and e.bits is None
    assert not any(f.startswith("weak-key-") for f in e.flags)  # unreadable is not weak (#143)
    assert e.undecided == ["key-size-unreadable"]  # and unreadable is not silence either (#148)


@needs_openssl
def test_a_curve_certificate_is_decided_exactly_like_its_private_key(tmp_path):
    """#149 made certificates report their algorithm, and left this asymmetry behind.

    A P-256 certificate and a P-256 private key are the same key, and this command has to answer
    about both the same way: #144 judged key strength per algorithm, #149 deferred the certificate
    side of it, #148 gave the note a column, and #162 emptied that column for EC. What is left to
    assert is that the answer is reached -- for either kind of entry, and identically.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, "p256", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"])  # writes a matching key
    by_kind = {e.kind: e for e in scan(fw)}
    assert by_kind["certificate"].curve_bits == by_kind["private-key"].curve_bits == 256
    assert by_kind["certificate"].undecided == []
    assert by_kind["private-key"].undecided == []
    assert not any("strength-undecided" in f for f in by_kind["certificate"].flags)
    assert not any("strength-undecided" in f for f in by_kind["certificate"].flags)


@needs_openssl
def test_a_fixed_curve_certificate_carries_no_undecided_note(tmp_path):
    """The symmetry must not make every certificate an unknown.

    ED25519 and ED448 are in DECIDED_ALGORITHMS and have no size to be unable to read, so a decision
    is reached and the note is absent -- the "checked, fine" answer from the other side (#148).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, "ed25519", ["ed25519"])
    (cert,) = [e for e in scan(fw) if e.kind == "certificate"]
    assert cert.algorithm == "ED25519" and cert.bits is None


# --- #162: `keys scan` reads the curve policy #151 wrote down, instead of deciding EC on its own ---


@needs_openssl
@pytest.mark.parametrize(("curve", "bits"), [("P-192", 192), ("P-224", 224)])
def test_a_curve_below_the_floor_is_a_weak_key(tmp_path, curve, bits):
    """The case from the issue: a P-192 key reported as `strength-undecided-ec`.

    `weak_key_verdict` rates the same key `high` in the capture path, off the constants #151 moved
    into `data_ciphers`, so one key was a finding in one command and an unknown in the other -- and
    "unknown" is the answer that keeps a deprecated curve off the list forever.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, "tiny-curve", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curve}")
    (e,) = scan(fw)
    assert e.algorithm == "EC"
    assert e.curve_bits == bits  # the curve size, in the slot its own threshold reads
    assert e.bits is None  # and never in the RSA one
    assert f"weak-key-{bits}bit" in e.flags
    assert e.undecided == []  # decided: weak is a verdict, not an absence of one


@needs_openssl
@pytest.mark.parametrize(("curve", "bits"), [("P-256", 256), ("P-384", 384), ("brainpoolP256r1", 256)])
def test_a_curve_at_or_above_the_floor_is_decided_and_silent(tmp_path, curve, bits):
    """P-256 is the smallest curve RFC 8422 still permits, so it is the boundary, not an edge case.

    Its curve size is at the floor, so there is nothing to report and nothing to admit: both columns
    empty, which #148 reserves for "checked, fine" (#162).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, "curve", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{curve}")
    (e,) = scan(fw)
    assert e.curve_bits == bits
    assert e.flags == [] and e.undecided == []


@pytest.mark.parametrize(("bits", "flagged"), [(MIN_EC_CURVE_BITS - 1, True), (MIN_EC_CURVE_BITS, False)])
def test_the_flag_boundary_is_exactly_the_documented_floor(bits, flagged):
    """One bit either side of MIN_EC_CURVE_BITS, because "at or above it" is the whole rule (#162).

    The entry is built rather than generated: the contract is the comparison, and no openssl build
    has to be able to make a P-255 for this to hold.
    """
    e = keys.KeyEntry(path="k.key", kind="private-key", algorithm="EC", curve_bits=bits)
    keys._flag([e])
    assert bool(e.flags) is flagged
    assert e.undecided == []  # decided either way: below the floor is weak, not unknown


def test_the_curve_floor_is_the_policy_constant_rather_than_a_number_written_here():
    """#151 moved these numbers out of a detector so a second consumer could read them (#162).

    If `keys scan` carries its own idea of how big a curve has to be, the capture path and this
    command can drift apart again, which is the whole complaint in the issue.
    """
    assert keys.MIN_EC_CURVE_BITS == data_ciphers.MIN_EC_CURVE_BITS


@needs_openssl
def test_the_threshold_follows_the_constant_instead_of_a_literal(tmp_path, monkeypatch):
    """Proof that the floor is read rather than copied: move it, and the verdict moves with it.

    A P-256 key is fine against the policy as written, and weak against a raised one -- which is
    only possible if the comparison is against the imported name (#162).
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _gen_key(fw, "p256", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    (before,) = scan(fw)
    assert before.flags == [] and before.curve_bits == 256  # decided, and fine
    monkeypatch.setattr(keys, "MIN_EC_CURVE_BITS", 384)
    (after,) = scan(fw)
    assert "weak-key-256bit" in after.flags  # the same key, under a policy that rejects it


@needs_openssl
def test_a_curve_certificate_is_judged_by_the_same_policy_as_its_private_key(tmp_path):
    """A certificate and its own key are the same key, and the two rows must not disagree (#162).

    Before this, the certificate had no curve size to judge at all and the key it certifies did, so
    the pair could report opposite verdicts about one piece of key material.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_alg_cert(fw, "tiny", ["ec", "-pkeyopt", "ec_paramgen_curve:P-192"])
    by_kind = {e.kind: e for e in scan(fw)}
    assert by_kind["certificate"].algorithm == by_kind["private-key"].algorithm == "EC"
    assert by_kind["certificate"].curve_bits == by_kind["private-key"].curve_bits == 192
    for e in by_kind.values():
        assert "weak-key-192bit" in e.flags
        assert e.undecided == []


def test_a_curve_certificate_below_the_floor_is_flagged_weak(tmp_path, monkeypatch):
    """The certificate half of the rule, from the dump openssl would print rather than a real one.

    Which curves a given openssl build can sign a certificate with varies; the contract under test
    does not. `_classify_canned_cert` hands over the text openssl writes, so this holds anywhere (#162).
    """
    cert = _classify_canned_cert(tmp_path, monkeypatch, "id-ecPublicKey", "                Public-Key: (192 bit)")
    assert cert.algorithm == "EC" and cert.curve_bits == 192
    assert cert.bits is None  # a curve size is not an RSA modulus (#143)
    assert "weak-key-192bit" in cert.flags
    assert cert.undecided == []


def test_a_curve_whose_size_openssl_will_not_read_says_so(tmp_path, monkeypatch):
    """A curve size we failed to read is not a weak curve -- and it is not silence either (#162).

    EC is decided by its size, so an EC key with no readable size is the same ignorance an RSA
    certificate with no readable modulus is, and it says so in the same words (#148).
    """
    cert = _classify_canned_cert(tmp_path, monkeypatch, "id-ecPublicKey", "                (no size here)")
    assert cert.algorithm == "EC" and cert.curve_bits is None
    assert not any(f.startswith("weak-key-") for f in cert.flags)  # unreadable is not weak
    assert cert.undecided == ["key-size-unreadable"]  # and unreadable is not silence


@needs_openssl
def test_a_dsa_certificate_is_not_measured_against_the_curve_floor(tmp_path):
    """The floor is a *curve* floor; there is still no DSA tier, and that is correct (#162).

    A DSA certificate prints a size the way a curve does, so reading it into the curve slot would
    judge a prime size against a threshold written about curves -- the borrowing of another rule that
    #143 and #155 both refused.
    """
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_dsa_cert(fw, "dsa", 2048)
    (cert,) = [e for e in scan(fw) if e.kind == "certificate"]
    assert cert.algorithm == "DSA"
    assert cert.curve_bits is None and cert.bits is None  # neither slot takes a DSA prime
    assert not any(f.startswith("weak-key-") for f in cert.flags)
    assert cert.undecided == ["strength-undecided-dsa"]


# --- #163: a certificate openssl cannot parse is a row that says why, not a file that vanished ---


def _broken_cert_tree(tmp_path, name="fs"):
    """The reproduction from the issue: one .crt-suffixed file that openssl will not parse."""
    fw = tmp_path / name
    (fw / "etc").mkdir(parents=True)
    (fw / "etc" / "broken.crt").write_text("not a certificate" + chr(10))
    return fw


def test_a_certificate_openssl_cannot_parse_is_reported_rather_than_dropped(tmp_path):
    """The case from the issue: `_classify_cert` returned None and `scan` skipped it.

    A file with a certificate suffix, in the place a firmware keeps its certificates, that openssl
    will not parse -- truncated, encrypted, a DER blob with the wrong header, a corrupted file -- used
    to produce no row, no flag and no note, and did not appear in the count either. That is a silent
    pass (AGENTS.md section 4), and it is now a row (#163).
    """
    fw = _broken_cert_tree(tmp_path)
    (entry,) = scan(fw)
    assert entry.path == "etc/broken.crt"  # the file is named, not merely counted
    assert entry.kind == "certificate"
    assert entry.undecided == ["certificate-unreadable"]


@needs_openssl
def test_a_tree_of_one_unreadable_certificate_does_not_report_a_clean_scan(cli_runner, tmp_path):
    """The comparison that made the original report: this tree, and an empty one.

    "0 private key(s), 0 certificate(s), 0 flagged, 0 undecided" is what a directory with nothing in
    it says, and it is exactly what a directory holding a file we could not read used to say as well.
    The summary has to be able to tell those two apart (#163).
    """
    broken = _broken_cert_tree(tmp_path, "broken")
    empty = tmp_path / "empty"
    (empty / "etc").mkdir(parents=True)
    summaries = {}
    for label, tree in (("broken", broken), ("empty", empty)):
        result = cli_runner.invoke(app, ["keys", "scan", str(tree)])
        assert result.exit_code == 0
        summaries[label] = _flat(result.output).split("key material")[0]
    assert summaries["broken"] != summaries["empty"]
    assert "0 certificate(s)" in summaries["empty"] and "0 undecided" in summaries["empty"]
    assert "1 certificate(s)" in summaries["broken"]  # it was counted
    assert "0 flagged" in summaries["broken"]  # and nothing was accused of anything
    assert "1 undecided" in summaries["broken"]  # it said which way it did not know


@needs_openssl
def test_the_unreadable_note_reaches_the_json_output(cli_runner, tmp_path):
    """--json is what a CI gate reads, so a note only in the table would not exist (#163)."""
    fw = _broken_cert_tree(tmp_path)
    result = cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    (entry,) = data["entries"]
    assert entry["path"] == "etc/broken.crt"
    assert entry["undecided"] == ["certificate-unreadable"] and entry["flags"] == []
    assert data["undecided"] == 1 and data["flagged"] == 0


def test_an_unreadable_certificate_gets_one_note_and_it_is_the_right_one(tmp_path):
    """Not "unreadable" *and* "strength-undecided-unknown-algorithm" (#163).

    Two notes would read as two findings and be one: we did not read a key, so its strength was never
    in question. The note that survives names what happened (#148).
    """
    (entry,) = scan(_broken_cert_tree(tmp_path))
    assert entry.undecided == [keys._UNREADABLE_CERT]


@needs_openssl
def test_an_unreadable_certificate_is_not_offered_to_analyze_as_a_key(cli_runner, tmp_path):
    """The row is an entry, but `--out` still only ships keys we could read (#163).

    `--out` feeds `analyze --keys-from`, which hands every file in the directory to openssl; shipping
    a file we could not parse would move the problem into the decryption path.
    """
    fw = _broken_cert_tree(tmp_path)
    _make_key_and_cert(fw / "etc", "srv", 1024)  # one readable key beside the broken file
    out = tmp_path / "keys.d"
    assert cli_runner.invoke(app, ["keys", "scan", str(fw), "--out", str(out)]).exit_code == 0
    assert [p.name for p in out.glob("*.pem")] == ["key000.pem"]  # the readable key, and only it


def test_a_markup_shaped_file_name_is_displayed_verbatim(cli_runner, tmp_path) -> None:
    """#174: rich renders table cells as markup, so [bold]x.pem displayed as x.pem.

    The analyst read a path that was not the file on disk, with no error and nothing visibly
    dropped. A deleted table would have been noticed; a wrong path is not.

    Asserts on the *displayed* text, not on escape bytes: a byte-count test passes trivially here and
    would not have caught this at all.
    """
    from scapy.all import PcapReader  # noqa: F401 - import guard only

    _markup_tree(tmp_path)
    result = cli_runner.invoke(app, ["keys", "scan", str(tmp_path / "tree")])
    assert result.exit_code == 0
    flat = " ".join(result.output.split())
    # rich folds long cells across lines, so the exact name is not reliably contiguous in the
    # rendered text. The invariant is that the brackets survived: before the fix rich consumed
    # [bold] and [red] as markup and displayed x.pem and z.pem.
    for tag in ("[bold]", "[red]", "a[b]c.pem"):
        assert tag in flat, f"{tag} did not survive into the display"
    assert "3 private key(s)" in flat, "the tree has three keys; the table must not have dropped one"


def _markup_tree(tmp_path) -> None:
    """A tree whose only file name is rich markup, so KEY_EXT cannot skip it and hide the bug."""
    from pcap_doctor.certificates import openssl_path

    openssl = openssl_path()
    if openssl is None:
        pytest.skip("openssl is required to make key material")
    root = tmp_path / "tree"
    root.mkdir(parents=True, exist_ok=True)
    key = root / "[bold]x.pem"
    subprocess.run([openssl, "genrsa", "-out", str(key), "2048"], capture_output=True, check=True)
    for name in ("[red]z.pem", "a[b]c.pem"):
        shutil.copy2(key, root / name)


def test_the_json_envelope_never_returns_a_control_character(cli_runner, tmp_path) -> None:
    """#175: json.dumps encodes ESC as \u001b, so counting bytes reported this surface clean.

    The question for JSON is not whether the file contains an escape byte -- it never does -- but
    whether *parsing* it yields a string containing a control character.
    """
    _markup_tree(tmp_path)
    result = cli_runner.invoke(app, ["keys", "scan", str(tmp_path / "tree"), "--json"])
    assert result.exit_code == 0
    entries = json.loads(result.stdout)["entries"]
    assert entries, "the tree has keys; an empty list would pass this test vacuously"
    for entry in entries:
        for field_name, value in entry.items():
            if isinstance(value, str):
                assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value), (
                    f"{field_name} carries a control character: {value[:60]!r}"
                )
