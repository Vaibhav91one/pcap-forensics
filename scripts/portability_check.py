#!/usr/bin/env python3
"""Cross-platform check used by CI on Linux, macOS and Windows (issue #108).

1. The installed ``pcap-doctor`` runs, ``pcap-doctor doctor`` passes, and every fixture yields exactly the
   finding codes in tests/fixtures/expected_codes.json: the same findings on every OS.
2. A real clipboard round trip through ``pcapforensics.clipboard.copy``, read back with the OS's own tool.

Usage: python scripts/portability_check.py [--no-clipboard]
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
TEXT = "pcap-doctor clipboard round trip ✓ ünïcode"


def pcap_doctor(*args: str) -> subprocess.CompletedProcess[str]:
    exe = shutil.which("pcap-doctor")
    if exe is None:
        sys.exit("pcap-doctor is not on PATH: install it first (pip install .)")
    return subprocess.run([exe, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)


def check_findings() -> list[str]:
    problems: list[str] = []
    version = pcap_doctor("--version")
    print(version.stdout.strip() or version.stderr.strip())
    doctor = pcap_doctor("doctor")
    if doctor.returncode != 0:
        problems.append(f"pcap-doctor doctor exited {doctor.returncode}: {doctor.stdout[-400:]}{doctor.stderr[-400:]}")
    expected: dict[str, list[str]] = json.loads((FIXTURES / "expected_codes.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        for name, codes in expected.items():
            run = pcap_doctor("analyze", str(FIXTURES / name), "-o", str(Path(tmp) / name), "-q", "--json")
            try:
                got = sorted({f["code"] for f in json.loads(run.stdout)["report"]["findings"]})
            except (ValueError, KeyError):
                problems.append(f"{name}: no JSON (exit {run.returncode}): {run.stderr[-400:]}")
                continue
            status = "ok" if got == codes else "MISMATCH"
            print(f"  {status:8} {name}: {', '.join(got) or '-'}")
            if got != codes:
                problems.append(f"{name}: expected {codes}, got {got}")
    return problems


def check_clipboard() -> list[str]:
    from pcapforensics.clipboard import OSC52, copy

    how = copy(TEXT, terminal=lambda _data: False)  # a real tool only: OSC 52 cannot be read back
    if not how or how == OSC52:
        return [f"no clipboard tool worked on {sys.platform} (copy returned {how!r})"]
    if sys.platform == "darwin":
        read = ["pbpaste"]
    elif sys.platform == "win32":
        read = ["powershell", "-NoProfile", "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard"]
    else:
        read = ["xclip", "-selection", "clipboard", "-o"]
    back = subprocess.run(read, capture_output=True, text=True, encoding="utf-8", check=False).stdout.rstrip("\r\n")
    print(f"  clipboard via {how}: {'ok' if back == TEXT else 'MISMATCH'}")
    return [] if back == TEXT else [f"clipboard via {how}: read back {back!r}"]


def main() -> int:
    problems = check_findings()
    if "--no-clipboard" not in sys.argv:
        problems += check_clipboard()
    for problem in problems:
        print(f"FAIL {problem}")
    print("portability check:", "FAILED" if problems else "passed", f"on {sys.platform}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
