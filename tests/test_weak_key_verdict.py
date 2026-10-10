"""weak_key_verdict: the size rule is an RSA rule (#152).

Every assertion here is about the *returned tuple*, not about prose, because what matters is that a
DSA key is never described as an RSA key and an unidentified algorithm is never quietly judged as RSA.

These are unit tests on a pure function. The end-to-end path that turns a verdict into a finding --
TLS_CERT_WEAK_KEY with its evidence table -- is covered in tests/test_detectors.py.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from pcap_doctor.certificates import openssl_path
from pcap_doctor.data_ciphers import DEPRECATED_EC_CURVE_BITS, MIN_EC_CURVE_BITS
from pcap_doctor.detectors.tls_cipher import weak_key_verdict


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


def test_the_curve_policy_is_the_documented_one() -> None:
    """The numbers are in docs/cipher-policy.md and in data_ciphers; they must not drift apart.

    The policy used to exist only as two literals inside the detector, which meant there was nothing
    to drift from and nothing to argue with. Now there is a documented threshold, so a change to one
    without the other should fail here rather than silently.
    """
    assert DEPRECATED_EC_CURVE_BITS < MIN_EC_CURVE_BITS
    policy = (Path(__file__).parent.parent / "docs" / "cipher-policy.md").read_text()

    # The numbers are checked against a machine-readable marker rather than by looking for them in
    # prose: "224" appears in the document for several unrelated reasons (secp224r1, P-224), so a
    # substring check passes even when the published boundary has changed underneath it.
    declared = re.search(
        r"<!-- curve-policy: deprecated_below=(\d+) minimum=(\d+) -->", policy
    )
    assert declared is not None, (
        "docs/cipher-policy.md must carry a '<!-- curve-policy: deprecated_below=N minimum=N -->' "
        "marker, or the published policy cannot be checked against the code"
    )
    assert int(declared.group(1)) == DEPRECATED_EC_CURVE_BITS
    assert int(declared.group(2)) == MIN_EC_CURVE_BITS

    # And the document must still say where the numbers come from, not just what they are.
    assert "RFC 8422" in policy, "the curve policy must cite the document it comes from"


def test_the_verdict_agrees_with_the_published_constants() -> None:
    """The literal 224/256 in the messages must be the constants, not stale copies."""
    below = weak_key_verdict("ec", DEPRECATED_EC_CURVE_BITS - 1)
    at_floor = weak_key_verdict("ec", DEPRECATED_EC_CURVE_BITS)
    at_min = weak_key_verdict("ec", MIN_EC_CURVE_BITS)
    assert below is not None and below[0] == "high"
    assert at_floor is not None and at_floor[0] == "medium"
    assert at_min is None
    assert str(DEPRECATED_EC_CURVE_BITS) in below[1]
    assert str(DEPRECATED_EC_CURVE_BITS) in at_floor[1]


def test_openssl_is_really_available() -> None:
    """Guard: the DSA test above skips silently if openssl went missing."""
    assert shutil.which("openssl") or openssl_path() is None
