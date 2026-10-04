"""Fetch the blobs the corpus manifest points at. Idempotent, verified, resumable.

    python scripts/corpus_fetch.py                      # everything in the manifest
    python scripts/corpus_fetch.py --kind firmware      # only the firmware images
    python scripts/corpus_fetch.py --limit 5            # a quick subset
    python scripts/corpus_fetch.py --verify             # re-hash what is on disk, fetch nothing

Blobs are large and gitignored. This script is the only thing that puts them there. Each blob gets a
PROVENANCE.json next to it recording the URL, the SHA-256 we computed, the byte count and the
timestamp, so a finding that depends on a corpus artefact can be traced back to the exact bytes.

A blob whose SHA-256 in the manifest is set is refused if it does not match. A blob whose manifest
SHA is null (every vendor artefact today) gets its computed digest written into its provenance file,
and a later run treats that file as the expected digest -- so a truncated or tampered download is
caught on the second run rather than the thirtieth.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import shutil
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BLOBS = ROOT / "corpus" / "blobs"
MANIFEST = ROOT / "corpus" / "manifest.json"
USER_AGENT = "pcap-doctor-corpus/0.6 (+https://github.com/Vaibhav91one/pcap-forensics)"
CHUNK = 1 << 20


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def provenance_path(blob_dir: Path) -> Path:
    return blob_dir / "PROVENANCE.json"


def load_provenance(blob_dir: Path) -> dict[str, Any]:
    path = provenance_path(blob_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def download(url: str, destination: Path, timeout: int = 180) -> None:
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response, temporary.open("wb") as handle:
        shutil.copyfileobj(response, handle, CHUNK)
    temporary.replace(destination)


def fetch_one(entry: dict[str, Any], verify_only: bool, timeout: int) -> dict[str, Any]:
    kind = entry["kind"]
    identifier = entry["id"]
    blob_dir = BLOBS / kind / identifier
    payload = blob_dir / (entry.get("name") or entry.get("file") or identifier)
    provenance_file = provenance_path(blob_dir)

    expected = entry.get("sha256") or load_provenance(blob_dir).get("sha256")
    record: dict[str, Any] = {"id": identifier, "kind": kind, "state": "skipped", "detail": ""}

    if not payload.exists():
        if verify_only:
            record["state"] = "missing"
            record["detail"] = "not on disk"
            return record
        blob_dir.mkdir(parents=True, exist_ok=True)
        try:
            download(entry["url"], payload, timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
            record["state"] = "failed"
            record["detail"] = f"{type(exc).__name__}: {exc}"
            return record
        record["state"] = "fetched"
    elif verify_only:
        record["state"] = "present"
    else:
        record["state"] = "present"

    digest = sha256_of(payload)
    if expected and expected != digest:
        record["state"] = "corrupt"
        record["detail"] = f"expected {expected[:16]}..., got {digest[:16]}..."
        return record

    if not verify_only:
        payload.stat()
        provenance_file.write_text(
            json.dumps(
                {
                    "id": identifier,
                    "kind": kind,
                    "url": entry["url"],
                    "sha256": digest,
                    "bytes": payload.stat().st_size,
                    "provenance": entry.get("provenance"),
                    "license": entry.get("license"),
                    "note": entry.get("note"),
                    "fetched_at": now(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    record["sha256"] = digest
    record["bytes"] = payload.stat().st_size
    record["detail"] = record["detail"] or str(payload.relative_to(ROOT))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch the corpus blobs.")
    parser.add_argument("--kind", choices=("firmware", "captures", "capture", "keymaterial"), default=None)
    parser.add_argument("--limit", type=int, default=0, help="only the first N of each kind")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--verify", action="store_true", help="re-hash what is on disk, fetch nothing")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    jobs: list[dict[str, Any]] = []
    for section, entries in sorted(manifest.items()):
        if not isinstance(entries, list):
            continue
        if args.kind and section != args.kind:
            continue
        jobs.extend(entries[: args.limit] if args.limit else entries)

    started = time.monotonic()
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(fetch_one, job, args.verify, args.timeout) for job in jobs]
        for done, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            record = future.result()
            results.append(record)
            if record["state"] not in ("skipped",):
                print(
                    f"[{done}/{len(jobs)}] {record['state']:8} {record['id']} "
                    f"{record.get('bytes', 0):>10,} B  {record['detail']}",
                    flush=True,
                )

    tally: dict[str, int] = {}
    for record in results:
        tally[record["state"]] = tally.get(record["state"], 0) + 1
    elapsed = time.monotonic() - started
    print(f"\n{len(results)} blob(s) in {elapsed:.1f}s: " + ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps({"elapsed_s": round(elapsed, 2), "tally": tally, "results": results}, indent=2) + "\n"
        )

    bad = tally.get("failed", 0) + tally.get("corrupt", 0)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
