"""Build ``corpus/manifest.json``: the committed index of the real-world stress corpus.

The manifest is committed; the blobs it points at are **not** (see `.gitignore`). Every entry
records where the artefact came from, what licence and provenance we have for it, and how large it
is, so a reviewer can decide whether to trust it before running `scripts/corpus_fetch.py`.

Sources are vendor download servers and public GitHub repositories -- published artefacts any
analyst can re-fetch. Nothing here is a capture of someone else's traffic.

    python scripts/corpus_manifest.py            # refresh corpus/manifest.json
    python scripts/corpus_manifest.py --check    # fail if the manifest no longer matches the sources

Design rules:
  * no guess-work URLs: directory listings are walked and filenames are taken verbatim
  * selection is deterministic (sorted, round-robin over device families) so the manifest is reviewable
  * blobs are large and stay out of git; the manifest plus a recorded SHA-256 is the contract
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "corpus" / "manifest.json"
USER_AGENT = "pcap-doctor-corpus/0.6 (+https://github.com/doctor-labs/pcap-doctor)"

# Seven releases, oldest first: seven years of a router OS that millions of devices run, each with a
# different base and a different shipped filesystem.
OPENWRT_RELEASES = ("17.01.7", "18.06.6", "19.07.10", "21.02.7", "22.03.7", "23.05.5", "24.10.0")

# Per-release cap. Twenty keeps the corpus in the low gigabytes while tripling the device diversity
# against the six-per-release first cut, which found no defects but also did not exercise many
# distinct firmware layouts. The source has ~1000 devices per release; twenty is breadth with a
# fetch time a person will actually wait for.
PER_RELEASE = 20

# Public GitHub repositories holding firmware artefacts, pinned to a tag or a commit so the corpus
# cannot change under us. Empty until a licence review clears an entry.
GITHUB_SOURCES: tuple[dict[str, Any], ...] = ()


# Real key material with properties known by construction: the openssl project's own test
# vectors. Unlike the firmware corpus these are not stock images -- they are the canonical corpus
# for X.509 and key-parsing edge cases, and the name says what each file is.
OPENSSL_CERTS = "https://raw.githubusercontent.com/openssl/openssl/master/test/certs/"

# (filename, expected flags). The expectation is what "keys scan" must report; the flags are keys
# scan's own vocabulary (see src/pcapforensics/cli/keys.py).
KNOWN_WEAK: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ca-key-768.pem", ("weak-key-768bit",)),
    ("ca-cert-768.pem", ("weak-key-768bit",)),
    ("ee-key-768.pem", ("weak-key-768bit",)),
    ("ee-cert-768.pem", ("weak-key-768bit",)),
    ("ee-key-1024.pem", ("weak-key-1024bit",)),
    ("ee-cert-1024.pem", ("weak-key-1024bit",)),
    ("root-key-768.pem", ("weak-key-768bit",)),
    ("root-cert-768.pem", ("weak-key-768bit",)),
)

# ee-expired2.pem is deliberately NOT here despite the name: openssl reports notAfter 2035-09-16, so
# it is valid today. The filename is a generation counter, not a promise. An oracle that trusts a
# filename instead of the bytes invents defects.
KNOWN_EXPIRED: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ca-expired.pem", ("expired",)),
    ("ee-expired.pem", ("expired",)),
    ("root-expired.pem", ("expired",)),
)

# A private key and the certificate carrying its public half, placed in one tree. Expected on the
# key: private-key-for-a-shipped-cert. On the cert: private-key-present. This is the finding that
# matters most in a firmware audit -- and the one the OpenWrt corpus cannot produce at all, because
# those images ship no device keys (dropbear generates host keys on first boot).
#
# The algorithms are deliberately spread: RSA, DSA, ECDSA on P-256/P-384, brainpool, Ed25519, Ed448
# and post-quantum ML-DSA. SPKI fingerprinting is exactly where exotic key types break, so they
# belong here.
KEY_AND_CERT: tuple[tuple[str, str], ...] = (
    ("ca-key.pem", "ca-cert.pem"),
    ("ee-key.pem", "ee-cert.pem"),
    ("root-key.pem", "root-cert.pem"),
    ("p256-server-key.pem", "p256-server-cert.pem"),
    ("p256-ee-rsa-ca-key.pem", "p256-ee-rsa-ca-cert.pem"),
    ("server-dsa-key.pem", "server-dsa-cert.pem"),
    ("server-ecdsa-key.pem", "server-ecdsa-cert.pem"),
    ("server-ed25519-key.pem", "server-ed25519-cert.pem"),
    ("server-ed448-key.pem", "server-ed448-cert.pem"),
    ("server-ecdsa-brainpoolP256r1-key.pem", "server-ecdsa-brainpoolP256r1-cert.pem"),
    ("p384-server-key.pem", "p384-server-cert.pem"),
    ("client-ed25519-key.pem", "client-ed25519-cert.pem"),
    ("pc1-key.pem", "pc1-cert.pem"),
)


def fetch(url: str, timeout: int = 30) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def entries(url: str) -> list[str]:
    """Every href in a directory listing, files included. Empty means "no listing", not an error."""
    try:
        body = fetch(url).decode("utf-8", "replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return []
    return [html.unescape(m.group(1)) for m in re.finditer(r'href="([^"]+)"', body)]


def listing(url: str) -> list[str]:
    """Only the sub-directories of a listing (those hrefs ending in a slash)."""
    return [name for name in entries(url) if name.endswith("/")]


def family_of(filename: str) -> str:
    """The SoC/target family from a sysupgrade filename (ramips-mt7620-ArcherC20i -> ramips).

    This is *not* a vendor. OpenWrt filenames do not reliably encode who made the box -- tp-link
    devices appear as ar71xx-generic-tl-mr6400-v1, zyxel ones as brcm63xx-generic-A4001N1 -- so the
    manifest records the family we can actually derive and leaves the vendor claim out.
    """
    device = device_of(filename)
    return re.sub(r"^(generic|nand|tiny)-", "", device).split("-")[0].lower()


def device_of(filename: str) -> str:
    return re.sub(r"^(lede|openwrt)-[\d.]+-", "", filename).replace("-squashfs-sysupgrade.bin", "")


def openwrt_candidates(release: str) -> list[dict[str, Any]]:
    base = f"https://downloads.openwrt.org/releases/{release}/targets/"
    rows: list[dict[str, Any]] = []
    for arch in sorted(name.rstrip("/") for name in listing(base)):
        if arch.startswith(("http", "?", "#")):
            continue
        for target in sorted(name.rstrip("/") for name in listing(f"{base}{arch}/")):
            if target.startswith(("http", "?", "#")):
                continue
            directory = f"{base}{arch}/{target}/"
            for name in sorted(entries(directory)):
                if not name.endswith("squashfs-sysupgrade.bin"):
                    continue
                rows.append(
                    {
                        "id": f"openwrt-{release}-{device_of(name)}",
                        "kind": "firmware",
                        "vendor": "openwrt",
                        "release": release,
                        "arch": arch,
                        "target": target,
                        "device": device_of(name),
                        "family": family_of(name),
                        "url": directory + name,
                        "bytes": None,
                        "sha256": None,
                        "provenance": "vendor download server, the OpenWrt project",
                        "license": "GPL-2.0 (OpenWrt firmware images)",
                        "note": "squashfs sysupgrade image for a real consumer device",
                    }
                )
    return rows


def select(rows: list[dict[str, Any]], per_release: int) -> list[dict[str, Any]]:
    """Round-robin over device families so one prolific SoC cannot fill the whole quota."""
    picked: list[dict[str, Any]] = []
    seen: set[str] = set()
    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_family.setdefault(row["family"], []).append(row)
    order = sorted(by_family, key=lambda family: (-len(by_family[family]), family))
    taken = 0
    while taken < per_release and any(by_family.values()):
        for family in order:
            bucket = by_family[family]
            if not bucket:
                continue
            row = bucket.pop(0)
            if row["device"] in seen:
                continue
            seen.add(row["device"])
            picked.append(row)
            taken += 1
            if taken >= per_release:
                break
    return picked


def github_captures() -> list[dict[str, Any]]:
    """Every capture in the wireshark test suite: real dissector input, some fuzzed on purpose."""
    raw = subprocess.run(
        ["gh", "api", "repos/wireshark/wireshark/contents/test/captures"],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout
    rows = []
    for entry in json.loads(raw):
        name = entry.get("name", "")
        if not name.endswith((".pcap", ".pcapng")):
            continue
        size, url = entry.get("size", 0), entry.get("download_url", "")
        rows.append(
            {
                "id": f"ws-{name}",
                "kind": "capture",
                "vendor": "wireshark",
                "name": name,
                "url": url,
                "bytes": int(size),
                "sha256": None,
                "provenance": "the wireshark project's own test suite (raw.githubusercontent.com)",
                "license": "GPL-2.0 (wireshark)",
                "note": "real dissector input; some are fuzzed, truncated or degenerate on purpose",
            }
        )
    return rows


def openssl_test_certs() -> set[str]:
    """Every filename under openssl's test/certs, fetched once and reused for verification."""
    raw = json.loads(fetch("https://api.github.com/repos/openssl/openssl/contents/test/certs?ref=master"))
    return {item["name"] for item in raw if item.get("name", "").endswith(".pem")}


# Elliptic-curve keys report their *curve* size in the bits field. Applying the RSA threshold
# (<=1024 bits) to that flags a P-256 key as weak, which is the opposite of the truth: EC P-256 is
# roughly RSA-3072 equivalent. These entries exist so the oracle asserts the absence of that flag.
EC_KEYS: tuple[tuple[str, str], ...] = (
    ("server-ecdsa-key.pem", "server-ecdsa-cert.pem"),
    ("server-ed25519-key.pem", "server-ed25519-cert.pem"),
    ("server-ed448-key.pem", "server-ed448-cert.pem"),
    ("server-ecdsa-brainpoolP256r1-key.pem", "server-ecdsa-brainpoolP256r1-cert.pem"),
    ("p256-server-key.pem", "p256-server-cert.pem"),
    ("p384-server-key.pem", "p384-server-cert.pem"),
)


def keymaterial() -> list[dict[str, Any]]:
    """Key-material blobs grouped into trees, each carrying what keys scan must report.

    Every named file is verified to exist upstream before the manifest is written. Guessing at a
    filename is the obvious failure mode here and it is a quiet one: the build succeeds and the
    download 404s an hour later, so the expectation silently never runs.
    """
    rows: list[dict[str, Any]] = []
    available = openssl_test_certs()
    named = {name for name, _ in KNOWN_WEAK} | {name for name, _ in KNOWN_EXPIRED}
    named |= {part for pair in KEY_AND_CERT for part in pair}
    absent = sorted(name for name in named if name not in available)
    if absent:
        raise SystemExit(
            "corpus_manifest: these key-material files do not exist under openssl test/certs: "
            + ", ".join(absent)
        )

    def add(group: str, name: str, expect: dict[str, Any]) -> None:
        rows.append(
            {
                "id": f"ossl-{group}-{name}",
                "kind": "keymaterial",
                "group": group,
                "vendor": "openssl",
                "name": name,
                "url": OPENSSL_CERTS + name,
                "bytes": None,
                "sha256": None,
                "expect": expect,
                "provenance": "the openssl project's own test vectors (raw.githubusercontent.com)",
                "license": "Apache-2.0 (openssl)",
                "note": "properties known by construction; the expectation is ground truth",
            }
        )

    for name, flags in KNOWN_WEAK:
        bits = 768 if "768" in name else 1024
        add("known-weak", name, {"kind": "certificate" if "cert" in name else "private-key",
                                 "bits": bits, "flags": list(flags)})
    for name, flags in KNOWN_EXPIRED:
        add("known-expired", name, {"kind": "certificate", "flags": list(flags)})
    for key, cert in KEY_AND_CERT:
        add("key-and-cert", key, {"kind": "private-key", "flags": ["private-key-for-a-shipped-cert"]})
        add("key-and-cert", cert, {"kind": "certificate", "flags": ["private-key-present"]})

    # EC keys: the pairing must still be found, and no weak-key flag may appear.
    curves = {"256": "server-ecdsa-key.pem", "384": "p384-server-key.pem"}
    for key, cert in EC_KEYS:
        curve = "256"
        for size in ("256", "384"):
            if size in key or size in cert:
                curve = size
        add("ec-keys", key, {
            "kind": "private-key",
            "flags": ["private-key-for-a-shipped-cert"],
            "forbid": [f"weak-key-{curve}bit"],
        })
        add("ec-keys", cert, {"kind": "certificate", "flags": ["private-key-present"]})
    _ = curves
    return rows


def build() -> dict[str, Any]:
    picked_by_release: dict[str, list[dict[str, Any]]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        results = list(pool.map(openwrt_candidates, OPENWRT_RELEASES))
    for release, rows in zip(OPENWRT_RELEASES, results, strict=True):
        picked_by_release[release] = select(rows, PER_RELEASE)

    firmware = [row for release in OPENWRT_RELEASES for row in picked_by_release[release]]
    captures = github_captures()
    firmware.extend(GITHUB_SOURCES)
    materials = keymaterial()

    return {
        "schema": 1,
        "tool": "pcap-doctor corpus",
        "tool_version": "0.6.0",
        "generated_by": "scripts/corpus_manifest.py",
        "policy": (
            "Published vendor downloads and public repositories only. No capture of anyone else's "
            "traffic, no private key material, no exploit payload. Blobs are not committed; this "
            "manifest plus the SHA-256 recorded at fetch time is the whole contract."
        ),
        "counts": {
            "firmware": len(firmware),
            "captures": len(captures),
            "keymaterial": len(materials),
        },
        "firmware": firmware,
        "captures": captures,
        "keymaterial": materials,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the committed corpus manifest.")
    parser.add_argument("--check", action="store_true", help="fail when the manifest is stale")
    args = parser.parse_args()

    manifest = build()
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.check:
        current = MANIFEST.read_text() if MANIFEST.exists() else ""
        if current != payload:
            print(
                "corpus/manifest.json is stale; run: python scripts/corpus_manifest.py",
                file=sys.stderr,
            )
            return 1
        print("corpus/manifest.json is current")
        return 0

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(payload)
    counts = manifest["counts"]
    print(
        f"wrote {MANIFEST.relative_to(ROOT)}: {counts['firmware']} firmware + "
        f"{counts['captures']} captures + {counts['keymaterial']} key material"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
