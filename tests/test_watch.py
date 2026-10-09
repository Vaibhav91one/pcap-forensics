"""`watch -i IFACE`: ring-buffer capture, analyze closed files only, print each finding id once (issue #64)."""

from __future__ import annotations

from pathlib import Path

from pcapforensics.cli import app
from pcapforensics.cli.watch import Watcher, capture_argv, capture_rights_hint
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
    monkeypatch.setattr("pcapforensics.cli.watch.sys.platform", "darwin")
    result = cli_runner.invoke(app, ["watch", "-i", "en0", "--dir", str(tmp_path / "ring")])
    assert result.exit_code == 2
    assert "permission to capture" in result.output and "access_bpf" in result.output


def test_capture_rights_hint_names_the_fix_for_each_os() -> None:
    # #128: the exact command for this OS, not a generic "needs root"
    assert "ChmodBPF" in capture_rights_hint("darwin")
    assert "setcap" in capture_rights_hint("linux") and "wireshark" in capture_rights_hint("linux")
    assert "Npcap" in capture_rights_hint("win32")
    assert "root" in capture_rights_hint("freebsd14")


def test_capture_failure_prints_the_linux_fix(cli_runner, tmp_path, monkeypatch) -> None:
    fake = tmp_path / "dumpcap"
    fake.write_text("#!/bin/sh\necho \"You don't have permission to capture on that device\" >&2\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setattr("pcapforensics.cli.watch.shutil.which", lambda t: str(fake) if t == "dumpcap" else None)
    monkeypatch.setattr("pcapforensics.cli.watch.POLL_SECONDS", 0.05)
    monkeypatch.setattr("pcapforensics.cli.watch.sys.platform", "linux")
    result = cli_runner.invoke(app, ["watch", "-i", "eth0", "--dir", str(tmp_path / "ring")])
    assert result.exit_code == 2
    assert "setcap cap_net_raw" in result.output


def _await_exit(pid: int, deadline_s: float = 5.0) -> int | None:
    # Wait for a child to actually disappear, and return its pid while it is still there.
    #
    # os.kill(pid, 0) succeeds for a process that has been killed but not yet reaped, because
    # the zombie still has an entry in the process table. Checking once therefore races the
    # reaper, which is why this test failed intermittently under load and passed every time it
    # ran alone. Polling for what the test actually cares about removes the race without
    # loosening the assertion.
    import os
    import time

    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        time.sleep(0.02)
    return pid

def _signal_when_started(pidfile, sig: int) -> None:
    import os
    import time

    deadline = time.monotonic() + 30
    while not (pidfile.exists() and pidfile.read_text().strip()) and time.monotonic() < deadline:
        time.sleep(0.02)
    os.kill(os.getpid(), sig)


def test_sigterm_and_an_ignored_sigint_still_stop_watch_cleanly(cli_runner, tmp_path, monkeypatch) -> None:
    # #128: `watch &` starts with SIGINT ignored, and service managers send SIGTERM; either must stop the capture
    import signal
    import threading

    pidfile = tmp_path / "dumpcap.pid"
    fake = tmp_path / "dumpcap"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nexec sleep 30\n")
    fake.chmod(0o755)
    monkeypatch.setattr("pcapforensics.cli.watch.shutil.which", lambda t: str(fake) if t == "dumpcap" else None)
    monkeypatch.setattr("pcapforensics.cli.watch.POLL_SECONDS", 0.05)
    before = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            pidfile.unlink(missing_ok=True)
            # signal once the fake capture has started; a fixed delay raced its startup under load (#190)
            threading.Thread(target=_signal_when_started, args=(pidfile, sig), daemon=True).start()
            result = cli_runner.invoke(app, ["watch", "-i", "lo", "--dir", str(tmp_path / f"ring{sig}")])
            assert result.exit_code == 0, result.output
            assert "stopped:" in result.output
            assert _await_exit(int(pidfile.read_text()), deadline_s=5.0) is None, (
                "the capture was still running after the stop")
        assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN  # watch put the old handlers back
    finally:
        signal.signal(signal.SIGINT, before)


def test_a_new_client_port_does_not_print_the_same_finding_again(tmp_path) -> None:
    # #136: every new connection to one service gets a new ephemeral port, so a new id; print it once
    def http(key: str) -> Finding:
        return Finding.make(detector="d2.transport_exposure", code="HTTP_CLEARTEXT", title=f"HTTP in cleartext on {key}",
                            severity="medium", confidence="high", category="x", summary="", scope=f"{key}|http",
                            flow_key=key)

    def report(*findings: Finding) -> Report:
        base = _report()
        return base.model_copy(update={"findings": list(findings)})

    first, again = http("tcp:127.0.0.1:8765<->127.0.0.1:45048"), http("tcp:127.0.0.1:8765<->127.0.0.1:45056")
    other_server = http("tcp:127.0.0.1:9000<->127.0.0.1:45060")
    results = {"ring_00001_a.pcapng": report(first), "ring_00002_b.pcapng": report(again, other_server)}
    for name in results:
        (tmp_path / name).write_bytes(b"")
    emitted: list[str] = []
    watcher = Watcher(tmp_path, lambda p: results[p.name], lambda f, p: emitted.append(f.flow_key or ""))
    watcher.step(final=True)
    assert first.id != again.id
    assert emitted == [first.flow_key, other_server.flow_key]
