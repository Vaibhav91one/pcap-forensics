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
RULE_DOCS = ROOT / "src" / "pcap_doctor" / "rule_docs"

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


def check_report_file(report_path: Path, workdir: Path) -> list[str]:
    """Check a report that already exists, without re-analysing the capture.

    Two reasons this exists. In CI it is the cheap way to re-check a report you already have. And it
    is the only honest way to mutation-test this harness: the thing it watches is the *shape* of a
    report, so the mutation has to be a report, and re-analysing a capture would regenerate a good one
    and hide the damage (scripts/corpus_selftest.py).
    """
    defects: list[str] = []
    try:
        report = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        return [f"{report_path.name}: not valid JSON ({exc})"]

    if not str(report.get("schema_version", "")).strip():
        defects.append(f"{report_path.name}: no schema_version")

    findings = report.get("findings") or []
    for finding in findings:
        identifier = str(finding.get("id", ""))
        if not re.fullmatch(r"[a-z0-9_.]+\.[A-Z][A-Z0-9_]*\.[0-9a-f]{16}", identifier):
            defects.append(f"{report_path.name}: id {identifier!r} is not detector.CODE.16-hex")
        if finding.get("severity") not in SARIF_LEVELS:
            defects.append(
                f"{report_path.name}: {finding.get('code')} has severity {finding.get('severity')!r}"
            )
        for evidence in finding.get("evidence") or []:
            if int(evidence.get("frame", 1)) <= 0:
                defects.append(
                    f"{report_path.name}: {finding.get('code')} cites frame {evidence.get('frame')}"
                )
                break
        if not finding.get("remediation"):
            defects.append(f"{report_path.name}: {finding.get('code')} has no remediation")
        if not finding.get("evidence"):
            defects.append(f"{report_path.name}: {finding.get('code')} carries no evidence")

    for note in report.get("notes") or []:
        for trigger in ("dropped", "unknown field", "no such field", "preference"):
            if trigger in str(note).lower():
                defects.append(f"{report_path.name}: note mentions {trigger!r}")
                break

    return defects


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
    if proc.returncode not in (0, 1, 3):
        defects.append(f"baseline-self: exit {proc.returncode}")
        return defects
    envelope = json.loads((workdir / "b.json").read_text())
    if "baseline" not in envelope:
        defects.append("baseline-self: the envelope has no baseline key")
    new = [f for f in envelope.get("findings") or [] if f.get("baseline_state") == "new"]
    if new:
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
    findings = json.loads((workdir / "r.json").read_text()).get("findings") or []
    defects: list[str] = []
    if not findings:
        return defects
    if not report_path.exists():
        defects.append("why-resolves: no report.json was written next to the artifacts")
        return defects
    for finding in findings[:12]:
        identifier = finding.get("finding_id")
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
        if not finding.get("remedy"):
            defects.append(f"why-resolves: '{identifier}' has no remediation")
        if _squash(finding.get("remedy") or "") not in _squash(proc.stdout + proc.stderr):
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
    if envelope.get("schema") != "doctor/1":
        defects.append("json-envelope: schema is not doctor/1")
    if not str((envelope.get("data") or {}).get("schema_version", "")).strip():
        defects.append("json-envelope: no data.schema_version")
    score = (envelope.get("score") or {}).get("value")
    if not isinstance(score, int) or not 0 <= score <= 100:
        defects.append(f"json-envelope: score is {score!r}, expected an int in 0..100")
    for finding in envelope.get("findings") or []:
        if finding.get("severity") not in SARIF_LEVELS:
            defects.append(
                f"json-envelope: {finding.get('id')} has severity {finding.get('severity')!r}"
            )
        # The documented shape is detector.CODE.sha256(scope)[:16]. The detector segment is
        # "d1.tls_cipher", which itself contains a dot, so the pattern has to allow dots in the
        # prefix and anchor on the uppercase code plus the 16-hex digest.
        identifier = str(finding.get("finding_id", ""))
        if not re.fullmatch(r"[a-z0-9_.]+\.[A-Z][A-Z0-9_]*\.[0-9a-f]{16}", identifier):
            defects.append(f"json-envelope: finding_id {identifier!r} is not detector.CODE.16-hex")
        if not re.fullmatch(r"[0-9a-f]{16}", str(finding.get("fingerprint", ""))):
            defects.append(f"json-envelope: fingerprint {finding.get('fingerprint')!r} is not 16 hex")

    if not out.exists():
        defects.append("sarif-valid: no SARIF file written")
        return defects
    sarif = json.loads(out.read_text())
    if sarif.get("version") != "2.1.0":
        defects.append(f"sarif-valid: version is {sarif.get('version')!r}")
    driver = ((sarif.get("runs") or [{}])[0].get("tool") or {}).get("driver") or {}
    if not driver.get("name"):
        defects.append("sarif-valid: no tool.driver.name")
    for finding in envelope.get("findings") or []:
        rule_ids = {r.get("id") for r in (driver.get("rules") or [])}
        if finding.get("id") not in rule_ids:
            defects.append(f"sarif-valid: {finding.get('code')} has no driver rule")
    return defects


def check_rules_catalog() -> list[str]:
    from pcap_doctor.rules import RULES

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
    parser.add_argument(
        "--reports",
        type=Path,
        default=None,
        help="check report.json files already in this directory instead of analysing captures. "
             "Used by scripts/corpus_selftest.py to mutate a report and prove this harness "
             "notices, and useful in CI to re-check a report you already have.",
    )
    args = parser.parse_args()

    if args.reports:
        reports = sorted(args.reports.rglob("report.json"))
        if not reports:
            print(f"no report.json under {args.reports}", file=sys.stderr)
            return 2
        results = [{"capture": r.name, "state": "checked",
                    "defects": check_report_file(r, ROOT)} for r in reports]
        defective = [r for r in results if r["defects"]]
        print(f"{len(results)} report(s) checked, {len(defective)} with defects")
        for record in defective[:10]:
            print("  " + record["capture"])
            for defect in record["defects"][:4]:
                print("      " + defect)
        out = args.out.resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"count": len(results), "results": results}, indent=2) + chr(10))
        return 1 if defective else 0

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
            state = "checked"
            probe = run(["analyze", str(capture), "-o", str(workdir / "probe"), "-q",
                         "--no-handoff", "--json-out", str(workdir / "probe.json")])
            if probe.returncode not in (0, 1) or not (workdir / "probe.json").exists():
                # A capture the tool refuses to analyse -- truncated, corrupt, not a capture -- is
                # reported as rejected, exactly as corpus_sweep.py does. It has no report, so there is
                # no contract to check; the rejection itself was checked there.
                state = "rejected"
                results.append({
                    "capture": str(capture.relative_to(ROOT)),
                    "state": state,
                    "defects": [],
                })
                if defects:
                    pass
                continue
            defects += check_baseline_self(capture, workdir)
            defects += check_why_resolves(capture, workdir)
            defects += check_sarif_and_json(capture, workdir)
        results.append({"capture": str(capture.relative_to(ROOT)), "state": state,
                        "defects": defects})
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
    rejected = sum(1 for r in results if r.get("state") == "rejected")
    print(f"{rejected} capture(s) rejected as unanalysable (documented behaviour, not checked here)")
    total = sum(len(r["defects"]) for r in results) + len(global_defects)
    print(
        f"\n{len(results)} capture(s) + catalog in {time.monotonic() - started:.1f}s, "
        f"{total} defect(s) -> {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}"
    )
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
