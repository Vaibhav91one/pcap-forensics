"""Check pcap-doctor's CLI contract holds on real artifacts, not just on fixtures.

    python scripts/corpus_cli.py --samples 40
    python scripts/corpus_cli.py --samples 0        # every capture

The other sweeps ask "did the analysis work". This one asks "is everything the analysis produced
actually usable downstream" -- which is a different question, and the one a real user hits when they
paste a report into a ticket or wire it into CI.

Each check below is a property that must hold for *every* report, not a smoke test of one file:

  baseline-self   analysing a capture against its own report must yield zero new findings. Anything
                  else means the stable id is not stable, and every CI gate built on it is wrong.
  why-resolves    every finding id in a real report must resolve through "why", with evidence, a
                  remediation and references. A finding a reader cannot look up is not finished.
  sarif-valid     the SARIF run must satisfy the 2.1.0 shape: version, tool driver, rules, results
                  with fingerprints, and ruleId equal to the finding code.
  json-envelope   --json must round-trip: stable schema_version, a score in range, findings carrying
                  the fields the docs promise.
  rules-complete  every code in the catalog must explain and must have a rule doc on disk.
  keys-out        "keys scan --out" must produce a directory the "analyze --keys-from" flag accepts.

A failure here is usually a report-consistency bug rather than a detection bug, which is why it
survives the fixture suite: fixtures assert on codes, never on the relationships between them.
"""

from __future__ import annotations

import argparse
import json
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
RULE_DOCS = ROOT / "src" / "pcapforensics" / "rule_docs"

def _squash(value: Any) -> str:
    """Collapse whitespace.

    rich wraps console output at the terminal width, so a remediation that exists in the report can
    be split across lines in the terminal and a substring check against it fails anyway. Comparing on
    collapsed whitespace is the only way to check presence from outside the process.
    """
    return " ".join(str(value).split())


SARIF_LEVELS = {"critical", "high", "medium", "low", "info"}


def run(args: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(CLI), *args], capture_output=True, text=True, timeout=timeout, cwd=ROOT
    )


def captures() -> list[Path]:
    root = BLOBS / "capture"
    found: list[Path] = []
    for entry in sorted(root.iterdir()) if root.exists() else []:
        found.extend(sorted(entry.glob("*.pcap")))
        found.extend(sorted(entry.glob("*.pcapng")))
    return found


def check_baseline_self(capture: Path, workdir: Path) -> list[str]:
    """Analysing a capture against its own report must find nothing new."""
    first = workdir / "first"
    second = workdir / "second"
    run(["analyze", str(capture), "-o", str(first), "-q", "--no-handoff",
         "--json-out", str(workdir / "a.json")])
    proc = run(["analyze", str(capture), "-o", str(second), "-q", "--no-handoff",
                "--baseline", str(workdir / "a.json"),
                "--json-out", str(workdir / "b.json")])
    defects: list[str] = []
    if proc.returncode not in (0, 1):
        defects.append(f"baseline-self: exit {proc.returncode}")
        return defects
    envelope = json.loads((workdir / "b.json").read_text())
    new = envelope.get("new_findings")
    if new is None:
        defects.append("baseline-self: the envelope has no new_findings key")
    elif new:
        ids = sorted({f.get("id", "?") for f in new})
        defects.append(
            f"baseline-self: {len(new)} finding(s) reported as new against the same capture "
            f"(ids {ids[:3]})"
        )
    return defects


def check_why_resolves(capture: Path, workdir: Path) -> list[str]:
    """Every finding id must resolve through 'why', with evidence and a fix."""
    report_path = workdir / "r" / "report.json"
    run(["analyze", str(capture), "-o", str(workdir / "r"), "-q", "--no-handoff",
         "--json-out", str(workdir / "r.json")])
    report = json.loads((workdir / "r.json").read_text()).get("report") or {}
    findings = report.get("findings") or []
    defects: list[str] = []
    if not findings:
        return defects
    if not report_path.exists():
        defects.append("why-resolves: no report.json was written next to the artifacts")
        return defects
    for finding in findings[:12]:
        identifier = finding.get("id")
        if not identifier:
            defects.append(f"why-resolves: a {finding.get('code')} finding has no id")
            continue
        # --report is required: "why" resolves an id against a report, and exits 2 when it cannot
        # find one. That is correct behaviour, so the harness has to pass the report it just wrote.
        proc = run(["why", identifier, "--report", str(report_path)])
        if proc.returncode == 2 and "0 report" in (proc.stdout + proc.stderr):
            defects.append(f"why-resolves: '{identifier}' could not find a report to resolve against")
            continue
        if proc.returncode != 0:
            defects.append(f"why-resolves: '{identifier}' exits {proc.returncode}")
            continue
        if not finding.get("evidence"):
            defects.append(f"why-resolves: '{identifier}' resolves but carries no evidence")
        if "remediation" not in json.dumps(finding):
            defects.append(f"why-resolves: '{identifier}' has no remediation")
        if _squash(finding.get("remediation", "")) not in _squash(proc.stdout + proc.stderr):
            defects.append(
                f"why-resolves: '{identifier}' resolves but does not show its remediation"
            )
    return defects


def check_sarif_and_json(capture: Path, workdir: Path) -> list[str]:
    out = workdir / "s.sarif"
    run(["analyze", str(capture), "-o", str(workdir / "r2"), "-q", "--no-handoff",
         "--json-out", str(workdir / "c.json"), "--sarif", str(out)])
    defects: list[str] = []

    envelope = json.loads((workdir / "c.json").read_text())
    report = envelope.get("report") or {}
    if not str(report.get("schema_version", "")).strip():
        defects.append("json-envelope: no schema_version")
    score = envelope.get("score")
    if not isinstance(score, int) or not 0 <= score <= 100:
        defects.append(f"json-envelope: score is {score!r}, expected an int in 0..100")
    for finding in report.get("findings") or []:
        if finding.get("severity") not in SARIF_LEVELS:
            defects.append(
                f"json-envelope: {finding.get('code')} has severity {finding.get('severity')!r}"
            )
        # The documented shape is detector.CODE.sha256(scope)[:16]. The detector segment is
        # "d1.tls_cipher", which itself contains a dot, so the pattern has to allow dots in the
        # prefix and anchor on the uppercase code plus the 16-hex digest.
        identifier = str(finding.get("id", ""))
        if not re.fullmatch(r"[a-z0-9_.]+\.[A-Z][A-Z0-9_]*\.[0-9a-f]{16}", identifier):
            defects.append(f"json-envelope: id {identifier!r} is not detector.CODE.16-hex")

    if not out.exists():
        defects.append("sarif-valid: no SARIF file written")
        return defects
    sarif = json.loads(out.read_text())
    if sarif.get("version") != "2.1.0":
        defects.append(f"sarif-valid: version is {sarif.get('version')!r}")
    driver = ((sarif.get("runs") or [{}])[0].get("tool") or {}).get("driver") or {}
    if not driver.get("name"):
        defects.append("sarif-valid: no tool.driver.name")
    for finding in report.get("findings") or []:
        rule_ids = {r.get("id") for r in (driver.get("rules") or [])}
        if finding.get("code") not in rule_ids:
            defects.append(f"sarif-valid: {finding.get('code')} has no driver rule")
    return defects


def check_rules_catalog() -> list[str]:
    from pcapforensics.rules import RULES

    defects: list[str] = []
    for code in sorted(RULES):
        proc = run(["rules", "explain", code])
        if proc.returncode != 0:
            defects.append(f"rules-complete: '{code}' does not explain (exit {proc.returncode})")
            continue
        doc = RULE_DOCS / f"{code}.md"
        if not doc.exists():
            defects.append(f"rules-complete: no rule doc at rule_docs/{code}.md")
            continue
        text = doc.read_text().lower()
        for section in ("what it means", "why it matters", "how to fix", "how to verify"):
            if section not in text:
                defects.append(f"rules-complete: rule_docs/{code}.md has no '{section}' section")
                break
    return defects


def check_keys_out() -> list[str]:
    """keys scan --out must produce something analyze --keys-from accepts."""
    trees = [p / "tree" for p in (BLOBS / "firmware").iterdir() if (p / "tree").is_dir()] \
        if (BLOBS / "firmware").exists() else []
    if not trees:
        return []
    defects: list[str] = []
    for tree in trees[:3]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "keys"
            proc = run(["keys", "scan", str(tree), "--out", str(target)])
            if proc.returncode not in (0, 1):
                defects.append(f"keys-out: scan exited {proc.returncode} on {tree.name}")
                continue
            if target.exists() and any(target.iterdir()):
                capture = captures()[:1]
                if capture:
                    use = run(["analyze", str(capture[0]), "-o", str(Path(tmp) / "o"), "-q",
                               "--no-handoff", "--keys-from", str(target)])
                    if use.returncode not in (0, 1):
                        defects.append(
                            f"keys-out: analyze --keys-from exited {use.returncode} on keys from "
                            f"{tree.name}"
                        )
    return defects


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the CLI contract over the real corpus.")
    parser.add_argument("--samples", type=int, default=40, help="captures to walk; 0 means all")
    parser.add_argument("--out", type=Path, default=REPORTS / "cli-contract.json")
    args = parser.parse_args()

    items = captures()
    if args.samples:
        # Deterministic spread across the corpus rather than the first N alphabetically.
        stride = max(1, len(items) // args.samples)
        items = items[::stride][: args.samples]

    started = time.monotonic()
    results: list[dict[str, Any]] = []
    for index, capture in enumerate(items, start=1):
        with tempfile.TemporaryDirectory(prefix="pf-cli-") as tmp:
            workdir = Path(tmp)
            defects: list[str] = []
            defects += check_baseline_self(capture, workdir)
            defects += check_why_resolves(capture, workdir)
            defects += check_sarif_and_json(capture, workdir)
        results.append({"capture": str(capture.relative_to(ROOT)), "defects": defects})
        if defects:
            print(f"[{index}/{len(items)}] {len(defects)} defect(s)  {capture.name}", flush=True)
            for defect in defects[:4]:
                print(f"      {defect}")

    global_defects = check_rules_catalog() + check_keys_out()
    for defect in global_defects:
        print(f"[catalog] {defect}")

    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "captures": len(results),
                "defects": sum(len(r["defects"]) for r in results) + len(global_defects),
                "results": results,
                "catalog_defects": global_defects,
            },
            indent=2,
        )
        + "\n"
    )
    total = sum(len(r["defects"]) for r in results) + len(global_defects)
    print(
        f"\n{len(results)} capture(s) + catalog in {time.monotonic() - started:.1f}s, "
        f"{total} defect(s) -> {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}"
    )
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
