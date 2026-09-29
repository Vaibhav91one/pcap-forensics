#!/usr/bin/env python3
"""Generate ``src/pcapforensics/data/cipher_suites.json``.

Design decision: **no hand-typed suite table.** Names and ids come from
``data/cipher_names.tsv``, which is extracted from tshark's own value table
(``tshark -G values``, field ``tls.handshake.ciphersuite``) -- 424 suites,
authoritative, and verifiably consistent with the dissector that produced the
capture. An earlier hand-written table had 22 wrong ids; this removes the
whole class of bug.

Everything else -- key exchange, block cipher, MAC, forward secrecy, weakness
tags -- is *derived* from the IANA name, which encodes all of it
structurally::

    TLS_<KX>_WITH_<ENC>_<MAC>       e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_<ENC>_<MAC>                 e.g. TLS_RSA_WITH_AES_128_CBC_SHA (implicit RSA)
    TLS_AES_128_GCM_SHA256          TLS 1.3, no KX/MAC in the name

Derivation rules live in :func:`classify` and are unit tested against the
hand-verified expectations in ``tests/test_cipher_registry.py``.

Policy provenance (also in ``docs/cipher-policy.md``):

* RFC 9325 section 4.1 -- suites that MUST NOT / SHOULD NOT be negotiated,
* NIST SP 800-52r2 -- CBC / 3DES / static-RSA restrictions,
* RFC 7457 (Sweet32), RFC 7465 (RC4), RFC 6194 (SHA-1),
* the ``deprecation`` column is this project's policy, not a verbatim RFC column.

Usage::

    python scripts/gen_cipher_suites.py            # rebuild from the TSV
    python scripts/gen_cipher_suites.py --refresh  # re-extract the TSV from tshark
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "src" / "pcapforensics" / "data"
NAMES_TSV = DATA_DIR / "cipher_names.tsv"
OUT = DATA_DIR / "cipher_suites.json"

# --------------------------------------------------------------------------
# name -> parts
# --------------------------------------------------------------------------

#: Ephemeral (forward-secret) key exchange markers, longest first.
EPHEMERAL_KX = ("ECDHE", "DHE", "DHE_PSK", "PSK_DHE", "PKE_DHE")
#: Static key exchange markers.
STATIC_KX = ("DH_DSS", "DH_RSA", "ECDH_ECDSA", "ECDH_RSA", "SRP", "KRB5", "DSS", "RSA", "PSK", "DH", "ECDH")

AEAD_ENCS = {
    "AES_128_GCM",
    "AES_256_GCM",
    "AES_128_CCM",
    "AES_128_CCM_8",
    "AES_256_CCM",
    "AES_256_CCM_8",
    "CHACHA20_POLY1305",
    "ARIA_128_GCM",
    "ARIA_256_GCM",
    "CAMELLIA_128_GCM",
    "CAMELLIA_256_GCM",
    "SEED_GCM",
}

WEAK_ENCS = {
    "DES_CBC": ("DES", "single DES, 56-bit key"),
    "DES40_CBC": ("EXPORT_GRADE", "40-bit DES"),
    "3DES_EDE_CBC": ("3DES", "3DES is vulnerable to Sweet32 (RFC 7457)"),
    "RC4_128": ("RC4", "RC4 is broken (RFC 7465)"),
    "RC4_40": ("EXPORT_GRADE", "export-grade RC4"),
    "ARCFOUR_128": ("RC4", "RC4 is broken (RFC 7465)"),
    "RC2_CBC_40": ("EXPORT_GRADE", "export-grade RC2"),
    "RC2_CBC": ("RC2", "RC2 is a legacy cipher"),
    "IDEA_CBC": ("IDEA", "IDEA is withdrawn"),
    "SEED_CBC": ("SEED", "SEED is a legacy cipher"),
    "NULL": ("NULL_ENCRYPTION", "no encryption at all"),
    "DHE_RSA_EXPORT": ("EXPORT_GRADE", "export-grade key exchange"),
}

WEAK_MACS = {
    "MD5": "MD5 based MAC is collision-broken",
    "SHA": "SHA-1 based MAC is deprecated (RFC 6194)",
    "MD2": "MD2 is broken",
    "CRC32": "CRC32 is not a cryptographic MAC",
}

GOST = re.compile(r"GOST|28147|CNT|GMAC")
TLS13 = re.compile(r"^TLS_(AES_\d+_(GCM|CCM(?:_\d+)?)|CHACHA20_POLY1305)_SHA(\d+)$")

#: Suites whose name does not follow the IANA pattern, verified by hand.
OVERRIDES: dict[int, dict[str, object]] = {
    0x00FF: {"name": "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "tags": ["SIGNALING"], "deprecation": "signalling"},
    0x5600: {"name": "TLS_FALLBACK_SCSV", "tags": ["SIGNALING"], "deprecation": "signalling"},
}


def split_name(name: str) -> tuple[str, str, str]:
    """Return ``(kx, enc, mac)`` tokens derived from an IANA cipher-suite name."""
    body = name
    for prefix in ("TLS_", "SSL_", "DTLS_"):
        if body.startswith(prefix):
            body = body[len(prefix) :]
            break
    if "_EXPORT_WITH_" in body or body.endswith("_EXPORT"):
        body = body.replace("_EXPORT_WITH_", "_WITH_") + "_EXPORT"
    parts = body.split("_")
    if "WITH" in parts:
        idx = parts.index("WITH")
        kx = "_".join(parts[:idx])
        rest = parts[idx + 1 :]
    else:
        kx = ""
        rest = parts
    mac = ""
    for candidate in ("SHA384", "SHA256", "SHA224", "SHA1", "SHA", "MD5", "MD2", "CRC32", "NULL", "GMAC", "CCM", "GCM"):
        token = "SHA" if candidate == "SHA1" else candidate
        if rest and rest[-1] == token:
            mac = candidate
            rest = rest[:-1]
            break
        if rest and rest[-1] == "SHA" and candidate == "SHA":
            mac = "SHA"
            rest = rest[:-1]
            break
    if not mac:
        for candidate in ("SHA256", "SHA384", "SHA", "MD5", "GMAC"):
            if rest and rest[-1] == candidate:
                mac = candidate
                rest = rest[:-1]
                break
    enc = "_".join(rest)
    if mac in {"GCM", "CCM"} and enc:
        mac = "aead"
    return kx, enc, mac


def classify(hex_id: int, name: str) -> dict[str, object]:
    kx, enc, mac = split_name(name)
    tags: set[str] = set()

    if hex_id >> 8 == 0x13:
        tags.add("TLS13")
    if TLS13.match(name):
        kx, enc, mac = "tls13", enc, "aead"

    if enc in AEAD_ENCS or mac == "aead":
        tags.add("AEAD")
    for enc_name, (tag, _why) in WEAK_ENCS.items():
        if enc_name in enc or enc_name in name:
            tags.add(tag)
    if "EXPORT" in name:
        tags.add("EXPORT_GRADE")
    if "ANON" in name.upper():
        tags.add("ANONYMOUS")
    if GOST.search(name):
        tags.add("GOST")
    if "CBC" in enc or "CBC" in name:
        tags.add("CBC_MODE")
    if "CHACHA20_POLY1305" in name:
        tags.add("AEAD")
    for mac_name, _why in WEAK_MACS.items():
        if mac == mac_name or (mac_name == "SHA" and mac == "SHA1"):
            tags.add(f"{mac_name}_MAC")
    if ("40" in name or "EXPORT" in name) and "WEAK_KEY_BITS" in tags:
        tags.discard("WEAK_KEY_BITS")

    forward_secrecy = any(marker in kx or marker in name for marker in EPHEMERAL_KX) and "anon" not in name.lower()
    if hex_id >> 8 == 0x13:
        forward_secrecy = True
    if forward_secrecy:
        tags.add("PFS")
    else:
        tags.add("NO_FORWARD_SECRECY")
        if kx in {"RSA", ""} or "_RSA" in kx or kx == "RSA":
            tags.add("STATIC_RSA")
    if "SIGNAL" in name or name.endswith("SCSV"):
        tags.add("SIGNALING")
    if "CCM" in name:
        tags.add("IOT")

    deprecation = deprecation_for(tags, hex_id)
    out: dict[str, object] = {
        "id": hex_id,
        "hex": f"0x{hex_id:04x}",
        "name": name,
        "kx": kx or "implicit-rsa",
        "enc": enc or "none",
        "mac": mac or "none",
        "forward_secrecy": forward_secrecy,
        "tags": sorted(tags),
        "deprecation": deprecation,
    }
    if hex_id in OVERRIDES:
        out.update(OVERRIDES[hex_id])
        out["id"] = hex_id
        out["hex"] = f"0x{hex_id:04x}"
    return out


def deprecation_for(tags: set[str], hex_id: int) -> str:
    if "SIGNALING" in tags:
        return "signalling"
    prohibited = {
        "NULL_ENCRYPTION",
        "EXPORT_GRADE",
        "RC4",
        "RC2",
        "DES",
        "3DES",
        "IDEA",
        "SEED",
        "MD5_MAC",
        "MD2_MAC",
        "ANONYMOUS",
        "CRC32_MAC",
        "GOST",
    }
    if tags & prohibited:
        return "prohibited"
    if hex_id >> 8 == 0x13:
        return "recommended"
    if "NO_FORWARD_SECRECY" in tags:
        return "deprecated"
    if "CBC_MODE" in tags or "SHA1_MAC" in tags:
        return "legacy"
    if "AEAD" in tags:
        return "acceptable"
    return "legacy"


def refresh_names_tsv() -> int:
    out = subprocess.run(
        ["tshark", "-G", "values"], capture_output=True, text=True, check=True
    ).stdout
    rows: dict[int, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[1] == "tls.handshake.ciphersuite":
            try:
                rows[int(parts[2])] = parts[3]
            except ValueError:
                continue
    body = "".join(f"{value}\t{rows[value]}\n" for value in sorted(rows))
    NAMES_TSV.write_text("# id<TAB>name, extracted from `tshark -G values` (field tls.handshake.ciphersuite)\n" + body)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="re-extract cipher_names.tsv from tshark")
    args = parser.parse_args()

    if args.refresh:
        print(f"refreshed {NAMES_TSV} with {refresh_names_tsv()} suites")

    suites: dict[str, dict[str, object]] = {}
    for line in NAMES_TSV.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        raw_id, _, name = line.partition("\t")
        entry = classify(int(raw_id), name.strip())
        suites[str(entry["id"])] = entry

    payload = {
        "schema": "1.0.0",
        "description": "TLS/DTLS cipher suites with names from tshark and derived weakness tags.",
        "name_source": "tshark -G values (tls.handshake.ciphersuite), vendored in cipher_names.tsv",
        "policy_provenance": [
            "RFC 9325 section 4.1 - cipher suites that MUST NOT or SHOULD NOT be negotiated",
            "NIST SP 800-52r2 - allowed cipher suites for TLS",
            "RFC 7457 Sweet32, RFC 7465 RC4, RFC 6194 SHA-1 - why the legacy tier exists",
            "Project policy - the deprecation column is ours, see docs/cipher-policy.md",
        ],
        "suites": suites,
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    counts: dict[str, int] = {}
    for entry in suites.values():
        dep = str(entry["deprecation"])
        counts[dep] = counts.get(dep, 0) + 1
    print(f"wrote {OUT.relative_to(ROOT)} ({len(suites)} suites)")
    for tier in sorted(counts):
        print(f"  {tier:12s} {counts[tier]}")


if __name__ == "__main__":
    main()
