"""`watch -i IFACE`: ring-buffer capture, analyze closed files only, print each finding id once (issue #64)."""

from __future__ import annotations

from pathlib import Path

from pcapforensics.cli import app
from pcapforensics.cli.watch import Watcher, capture_argv
from pcapforensics.models import CaptureInfo, Finding, Report, Stats


def _report(*codes: str) -> Report:
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    findings = [
        Finding.make(detector="d1.tls_cipher", code=c, title=c, severity="high", confidence="high", category="crypto",
                     summary="", scope=c)
        for c in codes
    ]
    return Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=findings)


def test_capture_argv_prefers_dumpcap_then_tshark(tmp_path) -> None:
    argv = capture_argv("en0", tmp_path, 30, 5, which=lambda t: t)
    assert argv == ["dumpcap", "-i", "en0", "-q", "-b", "duration:30", "-b", "files:5", "-w", str(tmp_path / "ring.pcapng")]
    assert capture_argv("en0", tmp_path, 30, 5, which=lambda t: t if t == "tshark" else None)[0] == "tshark"
    assert capture_argv("en0", tmp_path, 30, 5, which=lambda t: None) is None


def test_only_closed_files_are_analyzed_and_each_id_is_printed_once(tmp_path) -> None:
    for name in ("ring_00001_a.pcapng", "ring_00002_b.pcapng", "other.txt"):
        (tmp_path / name).write_bytes(b"")
    results = {"ring_00001_a.pcapng": _report("A", "B"), "ring_00002_b.pcapng": _report("B", "C"),
               "ring_00003_c.pcapng": _report("C", "D")}
    analyzed: list[str] = []
    emitted: list[tuple[str, str]] = []

    def analyze_fn(path: Path) -> Report:
        analyzed.append(path.name)
        return results[path.name]

    watcher = Watcher(tmp_path, analyze_fn, lambda f, p: emitted.append((f.code, p.name)))
    assert watcher.step() == 2  # ring_00002 is still being written
    assert analyzed == ["ring_00001_a.pcapng"]
    assert watcher.step() == 0  # nothing new closed, nothing analyzed twice
    (tmp_path / "ring_00003_c.pcapng").write_bytes(b"")
    assert watcher.step() == 1  # ring_00002 closed: B was already printed, C is new
    assert watcher.step(final=True) == 1  # on stop the last file counts too: only D is new
    assert analyzed == ["ring_00001_a.pcapng", "ring_00002_b.pcapng", "ring_00003_c.pcapng"]
    assert emitted == [("A", "ring_00001_a.pcapng"), ("B", "ring_00001_a.pcapng"), ("C", "ring_00002_b.pcapng"),
                       ("D", "ring_00003_c.pcapng")]


def test_missing_capture_tool_exits_2(cli_runner, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("pcapforensics.cli.watch.shutil.which", lambda _t: None)
    result = cli_runner.invoke(app, ["watch", "-i", "en0", "--dir", str(tmp_path)])
    assert result.exit_code == 2 and "dumpcap or tshark" in result.output


def test_capture_failure_exits_2_with_the_tool_error(cli_runner, tmp_path, monkeypatch) -> None:
    fake = tmp_path / "dumpcap"
    fake.write_text("#!/bin/sh\necho \"You don't have permission to capture on that device\" >&2\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setattr("pcapforensics.cli.watch.shutil.which", lambda t: str(fake) if t == "dumpcap" else None)
    monkeypatch.setattr("pcapforensics.cli.watch.POLL_SECONDS", 0.05)
    result = cli_runner.invoke(app, ["watch", "-i", "en0", "--dir", str(tmp_path / "ring")])
    assert result.exit_code == 2
    assert "permission to capture" in result.output and "access_bpf" in result.output
