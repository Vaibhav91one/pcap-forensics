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
