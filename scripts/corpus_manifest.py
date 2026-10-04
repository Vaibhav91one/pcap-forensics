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
USER_AGENT = "pcap-doctor-corpus/0.6 (+https://github.com/Vaibhav91one/pcap-forensics)"

# Seven releases, oldest first: seven years of a router OS that millions of devices run, each with a
# different base and a different shipped filesystem.
OPENWRT_RELEASES = ("17.01.7", "18.06.6", "19.07.10", "21.02.7", "22.03.7", "23.05.5", "24.10.0")

# Per-release cap: keeps the corpus in the hundreds of MB while spanning every release.
PER_RELEASE = 6

# Public GitHub repositories holding firmware artefacts, pinned to a tag or a commit so the corpus
# cannot change under us. Empty until a licence review clears an entry.
GITHUB_SOURCES: tuple[dict[str, Any], ...] = ()


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


def build() -> dict[str, Any]:
    picked_by_release: dict[str, list[dict[str, Any]]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        results = list(pool.map(openwrt_candidates, OPENWRT_RELEASES))
    for release, rows in zip(OPENWRT_RELEASES, results, strict=True):
        picked_by_release[release] = select(rows, PER_RELEASE)

    firmware = [row for release in OPENWRT_RELEASES for row in picked_by_release[release]]
    captures = github_captures()
    firmware.extend(GITHUB_SOURCES)

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
        "counts": {"firmware": len(firmware), "captures": len(captures)},
        "firmware": firmware,
        "captures": captures,
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
    print(f"wrote {MANIFEST.relative_to(ROOT)}: {counts['firmware']} firmware + {counts['captures']} captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
