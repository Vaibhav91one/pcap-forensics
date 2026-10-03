"""Copy works on any machine and never claims a copy that did not happen; the findings report (issue #101)."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys

import pytest

from pcapforensics.clipboard import OSC52, commands, copy, encode_for, osc52
from pcapforensics.models import CaptureInfo, Evidence, Finding, Report, Stats
from pcapforensics.output import findings_report

ALL = lambda name: f"/usr/bin/{name}"  # noqa: E731 - every tool "installed"
NONE = lambda name: None  # noqa: E731
X11_REQUIRED = os.environ.get("PCAP_DOCTOR_REQUIRE_X11") == "1"  # set in CI, where xclip/xsel run under Xvfb


def test_tool_order_follows_the_session() -> None:
    def names(cmds: list[list[str]]) -> list[str]:
        return [c[0].rsplit("/", 1)[-1] for c in cmds]

    assert commands({}, ALL, "darwin")[0] == ["/usr/bin/pbcopy"]  # run by the resolved path
    assert names(commands({"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, ALL, "linux"))[:3] == ["wl-copy", "xclip", "xsel"]
    assert commands({"DISPLAY": ":0"}, ALL, "linux")[0] == ["/usr/bin/xclip", "-selection", "clipboard"]
    # Ubuntu over SSH or headless: no display, so no X11/Wayland tool is even tried
    assert names(commands({}, ALL, "linux")) == ["powershell.exe", "powershell", "clip.exe", "clip", "termux-clipboard-set"]
    assert commands({"DISPLAY": ":0"}, NONE, "linux") == []  # nothing installed


def test_first_working_tool_wins_and_failures_fall_through() -> None:
    tried: list[str] = []

    def run(argv: list[str], data: bytes) -> int:
        tried.append(argv[0])
        return 1 if argv[0].endswith("xclip") else 0

    assert copy("x", env={"DISPLAY": ":0"}, which=ALL, run=run, platform="linux", terminal=lambda b: False) == "xsel"
    assert tried == ["/usr/bin/xclip", "/usr/bin/xsel"]


def test_without_a_tool_it_uses_osc52_and_says_so() -> None:
    sent: list[bytes] = []
    how = copy("héllo", env={}, which=NONE, platform="linux", terminal=lambda b: sent.append(b) or True)
    assert how == OSC52 and sent == [osc52("héllo", {})]
    assert copy("x", env={}, which=NONE, platform="linux", terminal=lambda b: False) == ""


def test_osc52_bytes_plain_and_inside_tmux() -> None:
    payload = base64.b64encode("héllo 🔐".encode()).decode()
    assert osc52("héllo 🔐", {}) == f"\x1b]52;c;{payload}\x07".encode()
    wrapped = osc52("héllo 🔐", {"TMUX": "/tmp/tmux-501/default,1,0"})
    assert wrapped.startswith(b"\x1bPtmux;\x1b\x1b]52;c;") and wrapped.endswith(b"\x07\x1b\\")


def test_windows_prefers_powershell_and_drops_duplicate_paths() -> None:
    """clip.exe keeps the byte-order mark in the clipboard (seen on a real Windows runner): PowerShell goes first."""
    same = lambda name: "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" if name.startswith("powershell") else None  # noqa: E731
    cmds = commands({}, same, "win32")
    assert len(cmds) == 1 and cmds[0][-1].endswith("Set-Clipboard -Value ([Console]::In.ReadToEnd())")
    assert encode_for(cmds[0], "é") == "é".encode()  # UTF-8 on stdin, no byte-order mark


def test_windows_clip_gets_utf16_with_a_bom() -> None:
    assert encode_for(["/mnt/c/Windows/System32/clip.exe"], "é") == b"\xff\xfe\xe9\x00"
    assert encode_for(["xclip"], "é") == "é".encode()


@pytest.mark.skipif(sys.platform == "win32", reason="uses a shell script as the fake tool")
def test_a_real_subprocess_receives_the_exact_bytes(tmp_path) -> None:
    out = tmp_path / "got"
    tool = tmp_path / "xclip"
    tool.write_text(f"#!/bin/sh\ncat > {out}\n")
    tool.chmod(0o755)
    how = copy("findings ✓ ünïcode", env={"DISPLAY": ":0"}, which=lambda n: str(tool) if n == "xclip" else None,
               platform="linux", terminal=lambda b: False)
    assert how == "xclip" and out.read_text(encoding="utf-8") == "findings ✓ ünïcode"


@pytest.mark.parametrize(("tool", "read"), [("xclip", ["xclip", "-selection", "clipboard", "-o"]),
                                            ("xsel", ["xsel", "--clipboard", "--output"])])
def test_real_x11_clipboard_round_trip(tool: str, read: list[str]) -> None:
    if not (os.environ.get("DISPLAY") and shutil.which(tool)):
        if X11_REQUIRED:
            pytest.fail(f"{tool} under a display is required here (PCAP_DOCTOR_REQUIRE_X11=1)")
        pytest.skip(f"needs DISPLAY and {tool} (CI runs this under Xvfb on Ubuntu)")
    text = f"pcap-doctor {tool} round trip ✓"
    how = copy(text, env={"DISPLAY": os.environ["DISPLAY"]}, which=lambda n: shutil.which(n) if n == tool else None,
               terminal=lambda b: False)
    assert how == tool
    assert subprocess.run(read, capture_output=True, text=True, timeout=5, check=True).stdout == text


def _report(*findings: Finding) -> Report:
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=5, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=list(findings))


def _finding(code: str, severity: str, title: str, value: str = "v") -> Finding:
    return Finding.make(
        detector="d2.transport_exposure", code=code, title=title, severity=severity, confidence="high",
        category="x", summary="what was seen", scope=title, flow_key="tcp:10.0.0.1:1<->10.0.0.2:80",
        subjects=["10.0.0.2"], evidence=[Evidence(frame=3, field="http.host", value=value)],
        remediation="the fix", references=["CWE-319"],
    )


def test_findings_report_is_a_readable_weakness_report() -> None:
    report = _report(_finding("HTTP_CLEARTEXT", "medium", "HTTP in cleartext"),
                     _finding("HTTP_CLEARTEXT_AUTH", "critical", "Basic credentials in cleartext"))
    text = findings_report(report)
    assert text.startswith("# Security findings: x.pcap\n")
    assert "**Findings in this report:** 2 (1 critical, 1 medium)" in text
    assert text.index("| 1 | Critical | HTTP_CLEARTEXT_AUTH") < text.index("| 2 | Medium | HTTP_CLEARTEXT:")
    for part in ("**Impact:** Anyone on the network path", "**Description:** what was seen", "  - frame 3: `http.host` = `v`",
                 "**Remediation:** the fix", "**References:** CWE-319", "**Affected:** `tcp:10.0.0.1:1<->10.0.0.2:80` · hosts: 10.0.0.2",
                 "not proof of safety"):
        assert part in text
    single = findings_report(report, [report.findings[0]])
    assert "|---|" not in single and "**Findings in this report:** 1" in single


def test_findings_report_neutralises_hostile_capture_text() -> None:
    hostile = "evil | cell `code`\x1b[31m\nnew line"
    text = findings_report(_report(_finding("HTTP_CLEARTEXT", "high", hostile, value=hostile), _finding("DNS_CLEARTEXT", "low", "b")))
    assert "\x1b" not in text and "`code`" not in text
    table_row = next(line for line in text.splitlines() if line.startswith("| 1 |"))
    assert table_row.count(" | ") == 3 and "\\|" in table_row  # the pipe in the title cannot split the cell
    assert "  - frame 3: `http.host` = `evil \\| cell 'code' [31m new line`" in text


WAYLAND_REQUIRED = os.environ.get("PCAP_DOCTOR_REQUIRE_WAYLAND") == "1"  # set in CI, where wl-copy runs under headless sway


def test_real_wayland_clipboard_round_trip() -> None:
    # #129: the wl-copy path for real, not a fake: copy, then read it back with wl-paste
    if not (os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy") and shutil.which("wl-paste")):
        if WAYLAND_REQUIRED:
            pytest.fail("wl-copy under a Wayland compositor is required here (PCAP_DOCTOR_REQUIRE_WAYLAND=1)")
        pytest.skip("needs WAYLAND_DISPLAY and wl-clipboard (CI runs this under a headless sway on Ubuntu)")
    text = "pcap-doctor wl-copy round trip ✓ ünïcode"
    how = copy(text, env={"WAYLAND_DISPLAY": os.environ["WAYLAND_DISPLAY"]},
               which=lambda n: shutil.which(n) if n == "wl-copy" else None, platform="linux", terminal=lambda b: False)
    assert how == "wl-copy"
    pasted = subprocess.run(["wl-paste", "--no-newline"], capture_output=True, timeout=5, check=True).stdout
    assert pasted.decode("utf-8") == text
