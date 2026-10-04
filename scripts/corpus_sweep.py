"""Run pcap-doctor over a corpus and record what actually happened. The stress-test harness.

    python scripts/corpus_sweep.py --kind capture --sweep analyze
    python scripts/corpus_sweep.py --kind firmware --sweep keys-scan

Everything is measured, nothing is asserted here: this script's job is to produce evidence a human,
or a subagent writing an issue, can point at. A finding appears in this report only because
pcap-doctor emitted it on real bytes.

What counts as a defect, for the triage step downstream:

* crash       -- the process died or printed a traceback
* exit        -- an exit code other than 0/1 (1 is the --fail-on gate, which is not a defect)
* note-error  -- a note saying a field, protocol or preference was dropped, or a detector raised.
                 This is the self-healing layer admitting it is degraded, and it is the single most
                 valuable signal this sweep produces: it means tshark drift is being absorbed
                 instead of being reported.
* frame-zero  -- a finding citing frame 0, which cannot be opened in Wireshark
* no-report   -- no report.json was written at all

A capture that legitimately has nothing to report is not a defect; it is recorded as clean.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / ".venv" / "bin" / "pcap-doctor"
BLOBS = ROOT / "corpus" / "blobs"
REPORTS = ROOT / "corpus" / "reports"

TRACEBACK = re.compile(r"Traceback \(most recent call last\)")
NOTE_TRIGGERS = ("dropped", "unknown field", "no such field", "preference", "detector raised", "not available")


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def label_of(record: dict[str, Any]) -> str:
    return record.get("capture") or record.get("tree") or "?"


def defects_of(notes: list[str], findings: list[dict[str, Any]]) -> list[str]:
    defects: list[str] = []
    joined = " ".join(notes).lower()
    for trigger in NOTE_TRIGGERS:
        if trigger in joined:
            defects.append(f"note-error: a note mentions {trigger!r}")
            break
    for finding in findings:
        for evidence in finding.get("evidence", []):
            if int(evidence.get("frame", 1)) <= 0:
                defects.append(f"frame-zero: {finding.get('code')} cites frame 0")
                break
    return defects


def run_one(path: Path, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    record: dict[str, Any] = {
        "capture": str(path.relative_to(ROOT)),
        "bytes": path.stat().st_size,
        "state": "ok",
        "defects": [],
        "findings": [],
        "notes": [],
        "score": None,
        "exit_code": None,
        "stderr_tail": "",
    }
    with tempfile.TemporaryDirectory(prefix="pf-sweep-") as tmp:
        report_json = Path(tmp) / "report.json"
        argv = [
            str(CLI), "analyze", str(path),
            "--out", str(Path(tmp) / "out"),
            "--json-out", str(report_json),
            "--no-cache",
            "-q",
        ]
        env = dict(os.environ, PYTHONWARNINGS="error")
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT
            )
        except subprocess.TimeoutExpired:
            record.update(state="crash", defects=[f"timeout after {timeout}s"])
            record["seconds"] = round(time.monotonic() - started, 2)
            return record

        record["exit_code"] = proc.returncode
        record["stderr_tail"] = proc.stderr.strip()[-2000:]
        if TRACEBACK.search(proc.stderr) or TRACEBACK.search(proc.stdout):
            record["state"] = "crash"
            record["defects"].append("crash: traceback in output")
        elif proc.returncode not in (0, 1):
            # Exit 2 is documented as "bad input or environment". A truncated or corrupt capture is
            # bad input, and the tool names exactly what happened and how to repair it, so that is
            # correct behaviour rather than a crash. Only an unexplained exit 2 is a defect.
            explained = proc.returncode == 2 and re.search(
                r"(cut short|truncated|corrupt|cannot read|not a capture|not a pcap)",
                proc.stderr + proc.stdout,
                re.IGNORECASE,
            )
            if explained:
                record["state"] = "rejected"
                record["detail"] = "input rejected with an explanatory message (expected behaviour)"
            else:
                record["state"] = "crash"
                record["defects"].append(f"exit: unexplained exit code {proc.returncode}")

        if report_json.exists():
            try:
                envelope = json.loads(report_json.read_text())
            except json.JSONDecodeError as exc:
                record["defects"].append(f"no-report: report.json unreadable ({exc})")
                envelope = {}
            report = envelope.get("report") or {}
            record["score"] = envelope.get("score")
            record["findings"] = [
                {
                    "code": f.get("code"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                    "id": f.get("id"),
                    "scope": f.get("scope"),
                }
                for f in (report.get("findings") or [])
            ]
            record["notes"] = list(report.get("notes") or [])
        else:
            record["defects"].append("no-report: report.json missing")

    record["defects"].extend(defects_of(record["notes"], record["findings"]))
    if record["defects"] and record["state"] == "ok":
        record["state"] = "defective"
    record["seconds"] = round(time.monotonic() - started, 2)
    return record


def captures() -> list[Path]:
    root = BLOBS / "capture"
    if not root.exists():
        return []
    found: list[Path] = []
    for entry in sorted(root.iterdir()):
        found.extend(sorted(entry.glob("*.pcap")))
        found.extend(sorted(entry.glob("*.pcapng")))
    return found


def firmware_trees() -> list[Path]:
    root = BLOBS / "firmware"
    if not root.exists():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "tree").is_dir())


PEM_MARKER = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
# PEM labels that carry key material pcap-doctor is expected to inventory.
KEY_LABELS = {"RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
              "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"}
CERT_LABELS = {"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"}


def looks_textual(blob: bytes) -> bool:
    """True for a file a human would call text.

    The oracle has to skip binaries or it cries wolf: every mbedTLS build in this corpus carries
    compiled-in PEM *self-test vectors* inside libmbedcrypto.so, which are not device keys and which
    keys scan is right to ignore. A private key on a device lives in a text file, so the oracle only
    counts text.
    """
    if not blob:
        return False
    sample = blob[:8192]
    if b"\x00" in sample:
        return False
    printable = sum(1 for byte in sample if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(sample) >= 0.95


def pem_oracle(tree: Path) -> dict[str, Any]:
    """Count PEM blocks in text files by brute-force byte scan, independently of pcap-doctor.

    This is the sweep's ground truth. If a text file on the filesystem holds key material that
    keys scan does not report, that is a false negative -- the worst kind of bug in this tool,
    because a firmware audit that silently misses the key an attacker would use is worse than no
    audit at all.
    """
    counts: dict[str, int] = {}
    scanned = 0
    for path in tree.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > 8 * 1024 * 1024:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        if not looks_textual(blob):
            continue
        scanned += 1
        for label in PEM_MARKER.findall(blob):
            name = label.decode("ascii", "replace")
            counts[name] = counts.get(name, 0) + 1
    return {
        "text_files_scanned": scanned,
        "key_blocks": sum(counts.get(label, 0) for label in KEY_LABELS),
        "cert_blocks": sum(counts.get(label, 0) for label in CERT_LABELS),
        "labels": counts,
    }


def sweep_keys_scan(trees: list[Path], timeout: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for tree in trees:
        started = time.monotonic()
        record: dict[str, Any] = {"tree": str(tree.relative_to(ROOT)), "state": "ok", "defects": []}
        try:
            proc = subprocess.run(
                [str(CLI), "keys", "scan", str(tree), "--json"],
                capture_output=True, text=True, timeout=timeout, cwd=ROOT,
            )
            record["exit_code"] = proc.returncode
            record["stderr_tail"] = proc.stderr.strip()[-2000:]
            if TRACEBACK.search(proc.stderr):
                record.update(state="crash", defects=["crash: traceback"])
            elif proc.returncode not in (0, 1):
                record.update(state="crash", defects=[f"exit: unexpected exit code {proc.returncode}"])
            else:
                try:
                    payload = json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    record.update(state="defective", defects=[f"no-report: keys scan JSON unreadable ({exc})"])
                else:
                    entries = payload.get("entries") or []
                    keys = [e for e in entries if e.get("kind") == "private_key"]
                    certs = [e for e in entries if e.get("kind") == "certificate"]
                    record["keys"] = len(keys)
                    record["certs"] = len(certs)
                    record["entries"] = len(entries)
                    record["flags"] = sorted({flag for e in entries for flag in e.get("flags") or []})
                    oracle = pem_oracle(tree)
                    record["oracle"] = oracle
                    if oracle["key_blocks"] > len(keys):
                        record["state"] = "defective"
                        record["defects"].append(
                            f"false-negative: filesystem holds {oracle['key_blocks']} private-key PEM "
                            f"block(s), keys scan reported {len(keys)}"
                        )
                    elif oracle["cert_blocks"] > 0 and len(certs) == 0:
                        record["state"] = "defective"
                        record["defects"].append(
                            f"false-negative: filesystem holds {oracle['cert_blocks']} certificate PEM "
                            f"block(s), keys scan reported 0"
                        )
        except subprocess.TimeoutExpired:
            record.update(state="crash", defects=[f"timeout after {timeout}s"])
        record["seconds"] = round(time.monotonic() - started, 2)
        results.append(record)
    return results


def markdown(sweep: dict[str, Any]) -> str:
    clean = sum(1 for r in sweep["results"] if not r["defects"])
    lines = [
        f"# Corpus sweep: {sweep['sweep']}",
        "",
        f"- generated: {sweep['generated_at']}",
        f"- pcap-doctor: {sweep['tool_version']}",
        f"- items: {len(sweep['results'])}",
        f"- clean: {clean}",
        f"- defective: {len(sweep['results']) - clean}",
        "",
    ]
    results = sweep["results"]
    if results and "findings" in results[0]:
        codes: dict[str, int] = {}
        for record in results:
            for finding in record.get("findings", []):
                code = str(finding.get("code"))
                codes[code] = codes.get(code, 0) + 1
        lines += ["## Codes emitted across the corpus", ""]
        for code, count in sorted(codes.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- {code}: {count}")
        lines.append("")
    lines += ["## Defects", ""]
    bad = [r for r in results if r["defects"]]
    if not bad:
        lines.append("None.")
    for record in sorted(bad, key=label_of):
        lines.append(f"### {label_of(record)}")
        for defect in record["defects"]:
            lines.append(f"- {defect}")
        if record.get("stderr_tail"):
            lines += ["", "    " + record["stderr_tail"][-600:].replace("\n", "\n    ")]
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run pcap-doctor over the real-world corpus.")
    parser.add_argument("--kind", choices=("capture", "firmware"), default="capture")
    parser.add_argument("--sweep", choices=("analyze", "keys-scan"), default="analyze")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    version = subprocess.run(
        [str(CLI), "--version"], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()

    items = captures() if args.sweep == "analyze" else firmware_trees()
    if args.limit:
        items = items[: args.limit]

    started = time.monotonic()
    if args.sweep == "analyze":
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(lambda path: run_one(path, args.timeout), items))
    else:
        results = sweep_keys_scan(items, args.timeout)

    sweep = {
        "sweep": f"{args.kind}/{args.sweep}",
        "generated_at": now(),
        "tool_version": version,
        "count": len(results),
        "elapsed_s": round(time.monotonic() - started, 2),
        "results": sorted(results, key=label_of),
    }

    out = (args.out or REPORTS / f"sweep-{args.kind}-{args.sweep}.json").resolve()
    shown = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sweep, indent=2) + "\n")
    out.with_suffix(".md").write_text(markdown(sweep))

    defective = [r for r in results if r["defects"]]
    print(
        f"{len(results)} item(s) in {sweep['elapsed_s']}s -> {shown}\n"
        f"  clean={len(results) - len(defective)} defective={len(defective)}"
    )
    for record in defective[:15]:
        print(f"  {record['state']:9} {label_of(record)}: {'; '.join(record['defects'][:2])}")
    if len(defective) > 15:
        print(f"  ... and {len(defective) - 15} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
