"""Prove the corpus harnesses still fail when they should. The eighth oracle.

    python scripts/corpus_selftest.py
    python scripts/corpus_selftest.py --verbose

Every other check in this corpus reports a result. This one reports whether the checks are still
*asking*.

Seven times in this loop a harness reported something real and wrong, and every time the cause was the
same: the check measured a proxy for the thing claimed rather than the thing itself. A compiled-in test
vector counted as a device key. A DTLS filter asked tshark for fields DTLS does not have. A find -name
matched a directory, so an empty table looked clean. A byte count reported a JSON surface clean while
json.dumps had encoded the escape as \u001b.

A harness that has quietly stopped asking is worse than no harness, because it is trusted. This script
answers one question per harness: if the thing it watches goes wrong, does it notice?

The method is mutation. Take a harness that currently reports a clean result, break the thing it is
supposed to be watching, and require that it now reports a problem. A harness that stays quiet under
mutation has told you nothing, and this prints exactly that.

A passing run here means the sweeps are worth reading. A failing run means the green in the last round
meant nothing.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "corpus" / "reports"
PYTHON = sys.executable


def run(argv: list[str], timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, cwd=ROOT, timeout=timeout)


def check_corpus_expect(verbose: bool) -> tuple[bool, str]:
    """corpus_expect.py: corrupt the ground truth and require the checker to notice.

    The manifest says what keys scan *should* report. Flipping one expectation to something the tool
    does not produce is the smallest possible regression in the thing being watched, and a ground-truth
    checker that ignores its own ground truth is decorative.
    """
    manifest = json.loads((ROOT / "corpus" / "manifest.json").read_text())
    entries = manifest.get("keymaterial") or []
    if not entries:
        return False, "no keymaterial entries in the manifest"

    baseline = run([PYTHON, "scripts/corpus_expect.py"])
    if baseline.returncode != 0:
        return False, f"baseline is not clean (exit {baseline.returncode}); fix that first"

    with tempfile.TemporaryDirectory() as td:
        mutated = json.loads(json.dumps(manifest))
        target = next(e for e in mutated["keymaterial"] if e.get("expect"))
        # a bits value no real key has, so the comparison must fail
        target["expect"]["bits"] = 31337
        path = Path(td) / "mutated.json"
        path.write_text(json.dumps(mutated, indent=2))

        broken = run([PYTHON, "scripts/corpus_expect.py", "--manifest", str(path)])
        noticed = broken.returncode != 0
        detail = f"{target['id']}: bits forced to 31337 -> exit {broken.returncode}"
        if verbose and noticed:
            for line in broken.stdout.splitlines()[-4:]:
                print("      " + line)
        return noticed, detail


def check_corpus_hostile(verbose: bool) -> tuple[bool, str]:
    """corpus_hostile.py: revert the JSON fix and require the harness to notice.

    The hostile harness only proves anything if the same tree reports clean on the fixed build and
    dirty on the pre-fix one. That comparison was made by hand in round 13; this makes it repeatable.
    """
    baseline = run([PYTHON, "scripts/corpus_hostile.py"])
    if "0 problem(s)" not in baseline.stdout:
        return False, "baseline is not clean; fix that first"

    target = ROOT / "src" / "pcapforensics" / "cli" / "keys.py"
    try:
        head = run(["git", "log", "--format=%H", "-20", "--", str(target)], timeout=60)
        commits = [line for line in head.stdout.split() if line]
        if not commits:
            return False, "no git history for keys.py; cannot construct a pre-fix build"
        # the commit that introduced clean_capture_text into keys.py
        introducing = run(["git", "log", "-S", "clean_capture_text", "--format=%H", "--", str(target)],
                          timeout=60)
        parents = [c for c in introducing.stdout.split() if c]
        if not parents:
            return False, "clean_capture_text was never introduced; nothing to revert"
        pre_fix = run(["git", "show", f"{parents[0]}^:{target.relative_to(ROOT)}"], timeout=60)
        if pre_fix.returncode != 0:
            return False, f"could not read the pre-fix keys.py (exit {pre_fix.returncode})"
        keep = target.read_bytes()
        target.write_bytes(pre_fix.stdout.encode())
        for cache in (ROOT / "src").rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
        broken = run([PYTHON, "scripts/corpus_hostile.py"])
        target.write_bytes(keep)
        for cache in (ROOT / "src").rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
    finally:
        target.write_bytes(target.read_bytes())

    noticed = "0 problem(s)" not in broken.stdout
    detail = f"keys.py reverted before {parents[0][:8]} -> {broken.stdout.strip().splitlines()[-1]}"
    if verbose and noticed:
        for line in broken.stdout.strip().splitlines()[-3:]:
            print("      " + line)
    return noticed, detail


def clear_caches() -> None:
    for cache in (ROOT / "src").rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)


def check_corpus_sweep(verbose: bool) -> tuple[bool, str]:
    # corpus_sweep.py: disable a detector and require the sweep to notice the false negative.
    #
    # This harness exists to catch a capture tshark decodes and pcap-doctor then says nothing about.
    # The cheapest honest way to test that claim is to make it true: stub out d1, so a TLS capture
    # produces no sessions, and require the sweep to say so.
    #
    # The mutation has to be in the *tool*, because what is being watched is what the tool does with a
    # capture -- not what the corpus holds. Corrupting a capture instead would test the reader, not the
    # claim, which is the standing failure mode in this loop.
    #
    # Detection-only stub: scan() is untouched, so this cannot turn into a second keys_scan test.
    # Pick the mutation from what the run can actually see. A fixed choice is a trap: --limit takes
    # the first N captures in name order and those start with arp and cbor, which produce no findings
    # at all -- so a disabled detector changes nothing and the check reads MUTE while testing nothing.
    # Asking the sweep first is what makes the mutation observable rather than assumed.
    limit = 60
    run([PYTHON, "scripts/corpus_sweep.py", "--kind", "capture", "--limit", str(limit),
         "--workers", "4", "--out", "/tmp/selftest-sweep-clean.json"])
    clean_report = json.loads(Path("/tmp/selftest-sweep-clean.json").read_text())
    with_findings = [item for item in clean_report["results"] if item.get("findings")]
    if not with_findings:
        return False, "no capture in the first " + str(limit) + " produces a finding to remove"

    codes = sorted({f["code"] for f in with_findings[0]["findings"]})
    detector = _detector_file_for(codes[0])
    if detector is None:
        return False, "could not map code " + codes[0] + " to a detector file"
    marker = "    def detect(self, index: CaptureIndex) -> list[Finding]:"
    if marker not in detector.read_text():
        return False, "could not find the detect() entry point to stub in " + detector.name

    keep = detector.read_bytes()
    try:
        stub = keep.decode().replace(
            marker,
            marker + chr(10) + "        return []  # corpus_selftest mutation: detector disabled",
            1,
        )
        detector.write_text(stub)
        clear_caches()
        run([PYTHON, "scripts/corpus_sweep.py", "--kind", "capture", "--limit", str(limit),
             "--workers", "4", "--out", "/tmp/selftest-sweep-broken.json"])
        report = json.loads(Path("/tmp/selftest-sweep-broken.json").read_text())
        defects = [
            (item.get("capture", ""), defect)
            for item in report["results"]
            for defect in item.get("defects", [])
            if any(tag in defect for tag in ("false-negative", "false-positive", "suspect"))
        ]
    finally:
        detector.write_bytes(keep)
        clear_caches()

    if not defects:
        return False, detector.name + " was disabled and the sweep reported nothing at all"
    if verbose:
        for name, defect in defects[:3]:
            print("      " + Path(name).parent.name + ": " + defect)
    return True, detector.name + " disabled -> " + str(len(defects)) + " false-negative report(s)"


def _detector_file_for(code: str):
    """The detector module that emits a code, so the mutation is aimed by code rather than guessed."""
    sys.path.insert(0, str(ROOT / "src"))
    from pcapforensics.rules import RULES

    rule = RULES.get(code)
    if rule is None:
        return None
    return ROOT / "src" / "pcapforensics" / "detectors" / (rule.detector.split(".", 1)[1] + ".py")


def _first_finding(document):
    for finding in document.get("findings") or []:
        if finding.get("evidence"):
            return finding
    return (document.get("findings") or [{}])[0]


def check_corpus_cli(verbose: bool) -> tuple[bool, str]:
    # corpus_cli.py: corrupt a real report and require the contract check to notice.
    #
    # The thing this harness watches is the *shape* of a report -- stable ids, a real frame on every
    # finding, a remediation, a severity from the known set. So the mutation has to be a report, not a
    # capture: re-analysing would regenerate a good one and hide the damage.
    #
    # Four mutations rather than one, because a check that only notices a deleted field is barely a
    # check.
    fixture = ROOT / "tests" / "fixtures" / "http_basic.pcap"
    if not fixture.exists():
        return False, "fixture missing; cannot produce a report to mutate"

    def drop_schema(document):
        document.pop("schema_version", None)

    def break_id(document):
        _first_finding(document)["id"] = "not-a-fingerprint"

    def zero_frame(document):
        _first_finding(document)["evidence"][0]["frame"] = 0

    def drop_remediation(document):
        _first_finding(document).pop("remediation", None)

    mutations = (
        ("schema_version removed", drop_schema),
        ("id corrupted", break_id),
        ("evidence frame zeroed", zero_frame),
        ("remediation removed", drop_remediation),
    )

    missed = []
    for label, mutate in mutations:
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            produced = subprocess.run(
                [str(ROOT / ".venv/bin/pcap-doctor"), "analyze", str(fixture),
                 "-o", str(work / "out"), "-q", "--no-handoff"],
                capture_output=True, cwd=ROOT, timeout=300,
            )
            report_path = work / "out" / "report.json"
            if produced.returncode not in (0, 1) or not report_path.exists():
                return False, "could not produce a report to mutate"
            document = json.loads(report_path.read_text())
            if not document.get("findings"):
                return False, "the fixture produced no findings, so there is nothing to corrupt"

            clean = run([PYTHON, "scripts/corpus_cli.py", "--reports", str(work / "out")])
            mutate(document)
            report_path.write_text(json.dumps(document, indent=2))
            broken = run([PYTHON, "scripts/corpus_cli.py", "--reports", str(work / "out")])
            if clean.returncode != 0 or broken.returncode == 0:
                missed.append(label)
            elif verbose:
                for line in broken.stdout.strip().splitlines()[1:3]:
                    print("      " + label + ": " + line.strip())

    if missed:
        return False, "stayed quiet for: " + ", ".join(missed)
    return True, "all " + str(len(mutations)) + " report mutations noticed"

def check_board_is_reachable(_verbose: bool) -> tuple[bool, str]:
    """A sanity floor: the harnesses must exist and be runnable, whatever they report."""
    missing = [
        name for name in ("corpus_sweep.py", "corpus_expect.py", "corpus_cli.py", "corpus_hostile.py")
        if not (ROOT / "scripts" / name).exists()
    ]
    if missing:
        return False, "missing harness(es): " + ", ".join(missing)
    return True, "all four harnesses present"


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove the corpus harnesses still fail when they should.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    print("mutation check: does each harness still notice a broken thing?\n")
    results = []
    for name, check in (
        ("corpus_expect (ground truth corrupted)", check_corpus_expect),
        ("corpus_hostile (JSON fix reverted)", check_corpus_hostile),
        ("corpus_cli (report corrupted)", check_corpus_cli),
        ("corpus_sweep (detector disabled)", check_corpus_sweep),
        ("harnesses present", check_board_is_reachable),
    ):
        try:
            passed, detail = check(args.verbose)
        except (subprocess.TimeoutExpired, OSError) as exc:
            passed, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({"check": name, "noticed": passed, "detail": detail})
        print(f"  {'OK  ' if passed else 'MUTE'}  {name:42} {detail}")

    untrustworthy = [r["check"] for r in results if not r["noticed"]]
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "selftest.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "untrustworthy": untrustworthy,
                "results": results,
            },
            indent=2,
        )
        + chr(10)
    )

    if untrustworthy:
        print(f"\n{len(untrustworthy)} harness(es) stayed quiet under mutation. Their green in the "
              f"last round means nothing.")
        for name in untrustworthy:
            print(f"  - {name}")
        return 1
    print("\nEvery harness noticed. The green results are worth reading.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
