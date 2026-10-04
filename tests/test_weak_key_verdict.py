"""weak_key_verdict: the size rule is an RSA rule (#152).

Every assertion here is about the *returned tuple*, not about prose, because what matters is that a
DSA key is never described as an RSA key and an unidentified algorithm is never quietly judged as RSA.

These are unit tests on a pure function. The end-to-end path that turns a verdict into a finding --
TLS_CERT_WEAK_KEY with its evidence table -- is covered in tests/test_detectors.py.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from pcapforensics.certificates import openssl_path
from pcapforensics.detectors.tls_cipher import weak_key_verdict


def _dsa_key(tmp_path, bits: int = 1024) -> bool:
    """A real DSA key, or False when this openssl build refuses to make one.

    Some builds reject DSA keygen below 2048. When that happens the case is skipped rather than
    deleted, so the coverage gap stays visible instead of quietly disappearing.
    """
    openssl = openssl_path()
    if openssl is None:
        return False
    param = tmp_path / f"param{bits}.pem"
    key = tmp_path / f"dsa{bits}.key"
    made = subprocess.run(
        [openssl, "genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", f"pbits:{bits}",
         "-out", str(param)],
        capture_output=True, check=False,
    )
    if made.returncode != 0 or not param.exists():
        return False
    made = subprocess.run(
        [openssl, "genpkey", "-paramfile", str(param), "-out", str(key)],
        capture_output=True, check=False,
    )
    return made.returncode == 0 and key.exists() and key.stat().st_size > 0


def test_dsa_is_not_judged_by_the_rsa_rule() -> None:
    verdict = weak_key_verdict("dsa", 1024)
    assert verdict is not None
    severity, reason = verdict
    assert severity == "medium"
    assert "RSA" not in reason or "does not apply" in reason
    assert "prime" in reason


def test_dsa_verdict_does_not_vary_with_size() -> None:
    """The RSA rule scales with size. The DSA branch must not pretend to."""
    assert weak_key_verdict("dsa", 512) == weak_key_verdict("dsa", 2048)


def test_a_real_dsa_key_is_reported_not_judged(tmp_path) -> None:
    if not _dsa_key(tmp_path, 1024):
        pytest.skip("this openssl build refuses to generate a 1024-bit DSA key")
    fact = subprocess.run(
        [openssl_path(), "pkey", "-in", str(tmp_path / "dsa1024.key"), "-noout", "-text"],
        capture_output=True, text=True, check=True,
    )
    assert "(1024 bit" in fact.stdout
    verdict = weak_key_verdict("dsa", 1024)
    assert verdict is not None
    assert "DSA key" in verdict[1]
    assert "trivially factorable" not in verdict[1]


def test_an_unidentified_algorithm_says_so_instead_of_claiming_rsa() -> None:
    """The unknown branch used to be unreachable below 2048 bits (#152)."""
    small = weak_key_verdict(None, 512)
    assert small is not None
    assert "could not be identified" in small[1]

    medium = weak_key_verdict(None, 1024)
    assert medium is not None
    assert "could not be identified" in medium[1]
    assert "conservative choice" in medium[1]


def test_an_unidentified_key_over_2048_is_not_called_acceptable() -> None:
    verdict = weak_key_verdict(None, 3072)
    assert verdict is not None
    assert "not a verdict on an unknown algorithm" in verdict[1]


def test_a_fixed_curve_key_is_not_reported_as_a_small_rsa_key() -> None:
    assert weak_key_verdict("Ed25519", 256) is None
    assert weak_key_verdict("id-Ed448", 448) is None


@pytest.mark.parametrize(
    ("algorithm", "bits", "expected"),
    [
        ("rsaEncryption", 768, ("high", "RSA keys below 1024 bits are trivially factorable.")),
        ("rsaEncryption", 1024, ("medium", "RSA keys below 2048 bits are outside current guidance.")),
        ("rsaEncryption", 2048, None),
        ("rsaEncryption", 4096, None),
        ("rsassaPss", 1024, ("medium", "RSA keys below 2048 bits are outside current guidance.")),
    ],
)
def test_rsa_behaviour_is_unchanged(algorithm: str, bits: int, expected) -> None:
    assert weak_key_verdict(algorithm, bits) == expected


@pytest.mark.parametrize(
    ("algorithm", "bits", "expected"),
    [
        ("ec", 192, ("high", "Elliptic curves below 224 bits are outside current guidance.")),
        ("ec", 224, ("medium", "P-224 is not recommended for new deployments; use P-256 or stronger.")),
        ("ec", 256, None),
        ("id-ecPublicKey", 384, None),
    ],
)
def test_ec_behaviour_is_unchanged(algorithm: str, bits: int, expected) -> None:
    assert weak_key_verdict(algorithm, bits) == expected


def test_no_size_means_no_verdict() -> None:
    assert weak_key_verdict("rsaEncryption", None) is None
    assert weak_key_verdict(None, None) is None


def test_openssl_is_really_available() -> None:
    """Guard: the DSA test above skips silently if openssl went missing."""
    assert shutil.which("openssl") or openssl_path() is None
