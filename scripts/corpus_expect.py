"""Check keys scan against the corpus's ground truth. The oracle for the white-box path.

    python scripts/corpus_expect.py
    python scripts/corpus_expect.py --verbose

Every keymaterial entry in corpus/manifest.json carries an expect block: what pcap-doctor keys
scan is *supposed* to report for that file. The truth is known by construction -- these are the
openssl project's own test vectors, and the filename says what the file is (ee-key-1024.pem is a
1024-bit key, ca-expired.pem is expired).

So this is not a smoke test. It is a comparison against ground truth, and every disagreement is a
defect with a precise expected/actual:

* wrong kind   -- a private key classified as a certificate, or a file reported not at all
* wrong bits   -- a 1024-bit key reported as something else, or None
* missing flag -- a dangerous finding the scan failed to raise at all

Expectations are *required* flags, not an exact set. Demanding an exact match produced four false
positives on the first run, all of them mine: root CA certificates are genuinely self-signed, and a
weak key whose certificate ships beside it is genuinely flagged twice over. A file that reports more
than expected is not a defect, so --verbose lists the extras instead of failing on them.

The key-and-cert group is the one that matters most in a firmware audit: a private key whose public
half is in a shipped certificate means anyone holding the image can impersonate the device. The stock
OpenWrt firmware corpus cannot produce that finding, because those images ship no device keys --
dropbear generates host keys on first boot. These vectors can.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / ".venv" / "bin" / "pcap-doctor"
BLOBS = ROOT / "corpus" / "blobs" / "keymaterial"
TREES = ROOT / "corpus" / "blobs" / "keymaterial-trees"
REPORTS = ROOT / "corpus" / "reports"
MANIFEST = ROOT / "corpus" / "manifest.json"


def materialise(entries: list[dict[str, Any]]) -> dict[str, Path]:
    """Lay each group out as a real directory tree, so keys scan walks it as it would a firmware."""
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_group[entry["group"]].append(entry)
    trees: dict[str, Path] = {}
    for group, members in by_group.items():
        tree = TREES / group
        if tree.exists():
            shutil.rmtree(tree)
        tree.mkdir(parents=True)
        for entry in members:
            source = BLOBS / entry["id"] / entry["name"]
            if not source.exists():
                raise SystemExit(f"missing corpus blob: {source}")
            shutil.copy2(source, tree / entry["name"])
        trees[group] = tree
    return trees


def scan(tree: Path, cli: Path = CLI) -> list[dict[str, Any]]:
    proc = subprocess.run(
        [str(cli), "keys", "scan", str(tree), "--json"],
        capture_output=True, text=True, timeout=300, cwd=ROOT,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"keys scan failed on {tree}: rc={proc.returncode}\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout).get("entries") or []


def compare(entries: list[dict[str, Any]], reported: list[dict[str, Any]]) -> list[str]:
    by_name = {e["path"]: e for e in reported}
    defects: list[str] = []
    for entry in entries:
        name = entry["name"]
        expect = entry["expect"]
        got = by_name.get(name)
        if got is None:
            defects.append(f"{name}: not reported at all (expected kind={expect['kind']})")
            continue
        if got.get("kind") != expect["kind"]:
            defects.append(f"{name}: kind is {got.get('kind')!r}, expected {expect['kind']!r}")
        if "bits" in expect and got.get("bits") != expect["bits"]:
            defects.append(f"{name}: bits is {got.get('bits')!r}, expected {expect['bits']!r}")
        want = set(expect.get("flags") or [])
        have = set(got.get("flags") or [])
        for missing in sorted(want - have):
            defects.append(f"{name}: missing flag {missing!r} (reported {sorted(have) or 'none'})")
        for forbidden in sorted(expect.get("forbid") or []):
            if forbidden in have:
                defects.append(
                    f"{name}: forbidden flag {forbidden!r} was raised "
                    f"(reported {sorted(have)})"
                )
    unreported = sorted(set(by_name) - {e["name"] for e in entries})
    for name in unreported:
        defects.append(f"{name}: reported but not part of this corpus group")
    return defects


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare keys scan against known-good material.")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--pcap-doctor",
        type=Path,
        default=CLI,
        help="the pcap-doctor to test. Point this at a worktree's CLI when verifying a patch: "
             "the default shells out to this repo, which runs the committed code, not yours.",
    )
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    entries = manifest.get("keymaterial") or []
    if not entries:
        print("no keymaterial entries; run scripts/corpus_manifest.py", file=sys.stderr)
        return 2

    trees = materialise(entries)
    results: list[dict[str, Any]] = []
    total_defects = 0
    for group in sorted(trees):
        tree = trees[group]
        members = [e for e in entries if e["group"] == group]
        reported = scan(tree, args.pcap_doctor)
        defects = compare(members, reported)
        total_defects += len(defects)
        results.append(
            {
                "group": group,
                "tree": str(tree.relative_to(ROOT)),
                "files": len(members),
                "reported": len(reported),
                "defects": defects,
            }
        )
        flag = "OK " if not defects else "BAD"
        print(f"{flag} {group:16} {len(members):3} file(s) -> {len(reported):3} reported")
        for defect in defects:
            print(f"      {defect}")

    out = REPORTS / "expect-keys.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "groups": len(results),
                "files": len(entries),
                "defects": total_defects,
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        f"\n{len(entries)} file(s) in {len(results)} group(s), "
        f"{total_defects} defect(s) -> {out.relative_to(ROOT)}"
    )
    return 1 if total_defects else 0


if __name__ == "__main__":
    sys.exit(main())
