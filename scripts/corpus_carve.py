"""Carve the filesystem out of a firmware image so `pcap-doctor keys scan` can walk it.

pcap-doctor deliberately never unpacks an image itself (AGENTS.md: it consumes an already-extracted
tree, like binwalk's output). This script is the binwalk stand-in: it finds the root filesystem by
its magic bytes and hands back a plain directory.

    python scripts/corpus_carve.py                      # carve everything under corpus/blobs/firmware
    python scripts/corpus_carve.py --limit 3
    python scripts/corpus_carve.py --only openwrt-23.05.5-ramips-mt7621-ubnt_unifi-plus

Why magic-byte scanning and not binwalk: the PyPI binwalk distribution is a stub that cannot be
imported (no importable release exists), and adding a third-party unpacker to a security tool's
test corpus is a supply-chain risk for no gain. Scanning for the SquashFS superblock magic is a few
lines and fully deterministic.

A router sysupgrade image is usually a raw kernel partition followed by a SquashFS root filesystem,
but several magic bytes appear before the real rootfs -- JFFS2 in particular, because the kernel
partition itself is JFFS2-packed. So `file` mislabels these images: for every image in this corpus
it reports jffs2. Rather than trusting the first match we try *every* aligned SquashFS offset and
keep whichever extracts the most files.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import shutil
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BLOBS = ROOT / "corpus" / "blobs" / "firmware"
REPORTS = ROOT / "corpus" / "reports"

SQUASHFS_MAGIC = b"hsqs"
# Deeper than any real firmware tree, while still bounding symlink-loop damage.
MAX_DEPTH = 12


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def image_of(blob_dir: Path) -> Path | None:
    """The firmware image itself: the largest non-metadata file in the blob directory.

    Excluding metadata by name is not enough. CARVE.json is written by this script into the same
    directory, so a name allowlist silently picks it up on the second run and carves a 900-byte JSON
    file instead of the image. Taking the largest non-JSON file is stable across re-runs.
    """
    candidates = [
        path
        for path in sorted(blob_dir.iterdir())
        if path.is_file() and path.suffix.lower() != ".json" and not path.name.endswith(".part")
    ]
    return max(candidates, key=lambda path: path.stat().st_size) if candidates else None


def count_files(tree: Path) -> int:
    return sum(1 for path in tree.rglob("*") if path.is_file() or path.is_symlink())


def plausible_superblock(data: bytes, offset: int) -> bool:
    """Does a SquashFS 4.x superblock really start here?

    Relying on alignment instead is a trap: real root filesystems in these images sit at offsets like
    0x139a94, which is not a multiple of 4096, and a 4 KiB-alignment filter silently drops a third
    of the corpus. So we parse the superblock and check the fields that only a real one has:
    version 4.x, a power-of-two block size between 4 KiB and 1 MiB, and a bytes-used that fits.
    """
    if offset + 0x30 > len(data):
        return False
    block_size, compression = struct.unpack_from("<I", data, offset + 0x0C)[0],         struct.unpack_from("<H", data, offset + 0x14)[0]
    version_major, version_minor = struct.unpack_from("<HH", data, offset + 0x1C)
    bytes_used = struct.unpack_from("<Q", data, offset + 0x28)[0]
    if version_major != 4 or version_minor > 1:
        return False
    if block_size not in (4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576):
        return False
    if compression not in (1, 2, 3, 4, 5, 6):  # gzip, lzma, lzo, xz, lz4, zstd
        return False
    return 0 < bytes_used < len(data) - offset


def squashfs_offsets(image: Path) -> list[int]:
    """Every offset in the image that holds a plausible SquashFS 4.x superblock."""
    data = image.read_bytes()
    offsets: list[int] = []
    start = 0
    while True:
        found = data.find(SQUASHFS_MAGIC, start)
        if found < 0:
            break
        if plausible_superblock(data, found):
            offsets.append(found)
        start = found + 4
    return offsets


def try_offset(image: Path, offset: int, destination: Path) -> tuple[int, str]:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    try:
        proc = subprocess.run(
            [
                "unsquashfs", "-o", str(offset), "-d", str(destination),
                "-f", "-max-depth", str(MAX_DEPTH), "-no-progress", str(image),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        return 0, "timeout"
    count = count_files(destination)
    noise = (proc.stderr or proc.stdout).strip().splitlines()
    detail = f"rc={proc.returncode} {noise[-1] if noise else ''}"[:200]
    return count, detail


def carve(blob_dir: Path, force: bool) -> dict[str, Any]:
    started = time.monotonic()
    identifier = blob_dir.name
    tree = blob_dir / "tree"
    carve_file = blob_dir / "CARVE.json"
    image = image_of(blob_dir)

    record: dict[str, Any] = {"id": identifier, "state": "pending", "attempts": []}
    if image is None:
        record.update(state="failed", detail="no image file in the blob directory")
        return record
    record["image"] = str(image.relative_to(ROOT))
    record["image_bytes"] = image.stat().st_size

    if carve_file.exists() and tree.is_dir() and not force:
        try:
            previous = json.loads(carve_file.read_text())
        except json.JSONDecodeError:
            previous = {}
        if previous.get("state") == "carved" and previous.get("files"):
            return {**previous, "state": "carved", "reused": True, "seconds": 0.0}

    offsets = squashfs_offsets(image)
    record["squashfs_offsets"] = offsets[:16]
    if not offsets:
        record.update(state="failed", detail="no SquashFS superblock found")
        return record

    best = {"files": 0, "offset": -1, "detail": ""}
    for offset in offsets:
        count, detail = try_offset(image, offset, tree)
        record["attempts"].append({"offset": offset, "files": count, "detail": detail})
        if count > best["files"]:
            best = {"files": count, "offset": offset, "detail": detail}

    record["offset"] = best["offset"]
    record["files"] = best["files"]
    record["detail"] = best["detail"]
    record["tool"] = "unsquashfs"
    record["carved_at"] = now()
    record["seconds"] = round(time.monotonic() - started, 2)

    if best["files"] == 0:
        shutil.rmtree(tree, ignore_errors=True)
        record["state"] = "failed"
        return record

    record["state"] = "carved"
    carve_file.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Carve SquashFS roots out of firmware images.")
    parser.add_argument("--only", action="append", default=None, help="carve only this blob id")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--force", action="store_true", help="re-carve even when a tree exists")
    args = parser.parse_args()

    if not BLOBS.exists():
        print("no firmware blobs; run scripts/corpus_fetch.py --kind firmware", file=sys.stderr)
        return 2

    dirs = sorted(p for p in BLOBS.iterdir() if p.is_dir())
    if args.only:
        wanted = set(args.only)
        dirs = [p for p in dirs if p.name in wanted]
    if args.limit:
        dirs = dirs[: args.limit]

    started = time.monotonic()
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(carve, d, args.force): d for d in dirs}
        for done, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            record = future.result()
            results.append(record)
            print(
                f"[{done}/{len(dirs)}] {record['state']:7} {record['id']:52} "
                f"files={record.get('files', 0):>6}  off={record.get('offset', -1)}",
                flush=True,
            )

    results.sort(key=lambda r: r["id"])
    out = REPORTS / "carve-firmware.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "generated_at": now(),
                "count": len(results),
                "carved": sum(1 for r in results if r["state"] == "carved"),
                "failed": sum(1 for r in results if r["state"] == "failed"),
                "elapsed_s": round(time.monotonic() - started, 2),
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )

    carved = [r for r in results if r["state"] == "carved"]
    total_files = sum(r.get("files", 0) for r in carved)
    print(
        f"\n{len(carved)}/{len(results)} carved, {total_files:,} files total, "
        f"{time.monotonic() - started:.1f}s -> {out.relative_to(ROOT)}"
    )
    for record in results:
        if record["state"] != "carved":
            print(f"  FAILED {record['id']}: {record.get('detail')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
