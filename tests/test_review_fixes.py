"""Regression tests for the pcap-doctor final review (issue #89)."""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path

import pytest

from conftest import FIXTURES, requires_tshark
from pcapforensics.cli import app
from pcapforensics.cli.watch import Watcher
from pcapforensics.models import CaptureInfo, Finding, Report, Stats
from pcapforensics.prompts import clean
from pcapforensics.tshark import TsharkMissingError


def _truncated(tmp_path: Path) -> Path:
    path = tmp_path / "cut.pcap"
    path.write_bytes((FIXTURES / "weak_tls.pcap").read_bytes()[:600])  # cut inside the 4th packet
    return path


@requires_tshark
@pytest.mark.parametrize("command", [["analyze"], ["flows"], ["ciphers"]])
def test_a_truncated_capture_exits_2_not_1(cli_runner, tmp_path, cache_dir, command: list[str]) -> None:
    args = [*command, str(_truncated(tmp_path))] + (["-o", str(tmp_path / "r"), "--fail-on", "low"] if command == ["analyze"] else [])
    result = cli_runner.invoke(app, args)
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)  # a clean exit, not a traceback
    assert "editcap" in result.output


@pytest.mark.parametrize("command", ["flows", "ciphers"])
def test_missing_tshark_exits_2(cli_runner, command: str, monkeypatch) -> None:
    def missing(*_a: object, **_k: object) -> None:
        raise TsharkMissingError("tshark not found on PATH")

    # The runner is what raises when tshark is absent; the lookups behind it are lru_cached across tests.
    monkeypatch.setattr("pcapforensics.cli.inspect.TsharkRunner", missing)
    result = cli_runner.invoke(app, [command, str(FIXTURES / "weak_tls.pcap")])
    assert result.exit_code == 2 and isinstance(result.exception, SystemExit)


def test_why_with_a_malformed_report_exits_2(cli_runner, tmp_path) -> None:
    bad = tmp_path / "report.json"
    bad.write_text('{"not": "a report"}')
    result = cli_runner.invoke(app, ["why", "1", "--report", str(bad)])
    assert result.exit_code == 2 and "not a pcap-doctor report.json" in " ".join(result.output.split())  # rich wraps


@requires_tshark
@pytest.mark.parametrize("option", ["--json-out", "--sarif"])
def test_output_files_get_their_parent_directories(cli_runner, tmp_path, cache_dir, option: str) -> None:
    target = tmp_path / "new" / "dir" / "out.json"
    args = ["analyze", str(FIXTURES / "strong_tls13.pcap"), "-o", str(tmp_path / "r"), "-q", option, str(target)]
    result = cli_runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert target.is_file()


def test_clean_drops_invisible_and_bidi_characters() -> None:
    hostile = "a b c‮d​e﻿f⁦g‏h\ni`j"
    assert clean(hostile) == "a b c d e f g h i'j"


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


def test_watcher_skips_a_file_that_fails_to_analyze(tmp_path) -> None:
    for name in ("ring_00001_a.pcapng", "ring_00002_b.pcapng", "ring_00003_c.pcapng"):
        (tmp_path / name).write_bytes(b"")

    def analyze_fn(path: Path) -> Report:
        if path.name.startswith("ring_00001"):
            raise RuntimeError("tshark pass 'base' failed (exit 14):\ncut short")
        return _report("A")

    errors: list[str] = []
    emitted: list[str] = []
    watcher = Watcher(tmp_path, analyze_fn, lambda f, p: emitted.append(p.name), lambda p, e: errors.append(p.name))
    assert watcher.step() == 1
    assert errors == ["ring_00001_a.pcapng"] and emitted == ["ring_00002_b.pcapng"]


def test_watch_never_leaves_the_capture_running(cli_runner, tmp_path, monkeypatch) -> None:
    pidfile = tmp_path / "pid"
    fake = tmp_path / "dumpcap"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nwhile :; do sleep 1; done\n")
    fake.chmod(0o755)
    monkeypatch.setattr("pcapforensics.cli.watch.shutil.which", lambda t: str(fake) if t == "dumpcap" else None)
    monkeypatch.setattr("pcapforensics.cli.watch.POLL_SECONDS", 0.05)

    def boom(self, *, final: bool = False) -> int:
        if pidfile.exists():
            raise RuntimeError("unexpected failure while watching")
        return 0

    monkeypatch.setattr(Watcher, "step", boom)
    result = cli_runner.invoke(app, ["watch", "-i", "en0", "--dir", str(tmp_path / "ring")])
    assert isinstance(result.exception, RuntimeError)
    pid = int(pidfile.read_text())
    for _ in range(50):  # terminate() is asynchronous; communicate() has reaped it once watch returns
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        os.kill(pid, signal.SIGKILL)  # never leak the fake capture, even when the test fails
        pytest.fail(f"capture process {pid} is still running")
