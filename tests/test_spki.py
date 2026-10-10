"""A capture cert's SPKI fingerprint matches the same key found in firmware (#119)."""

from __future__ import annotations

import hashlib
import ssl
import subprocess

import pytest

from pcap_doctor.certificates import inspect_der, openssl_path, spki_sha256

needs_openssl = pytest.mark.skipif(openssl_path() is None, reason="needs openssl")


def test_spki_of_raw_der_is_16_hex() -> None:
    fp = spki_sha256(b"any-der-bytes")
    assert fp == hashlib.sha256(b"any-der-bytes").hexdigest()[:16]
    assert len(fp) == 16


@needs_openssl
def test_capture_cert_spki_matches_the_private_key_in_firmware(tmp_path) -> None:
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=t", "-keyout", str(key), "-out", str(crt)],
        capture_output=True, check=True,
    )
    # capture side: fingerprint read off the certificate seen on the wire
    der = ssl.PEM_cert_to_DER_cert(crt.read_text())
    from_capture = inspect_der(der).spki_sha256
    assert from_capture and len(from_capture) == 16
    # firmware side: fingerprint of the private key that ships in the image
    pub_der = subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    assert from_capture == spki_sha256(pub_der)  # they match -> the wire key is the firmware key
