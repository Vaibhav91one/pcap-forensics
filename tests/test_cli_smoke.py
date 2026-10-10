"""The command line is a package of self-registering command modules (issue #45)."""

from __future__ import annotations

import subprocess
import sys

from pcap_doctor.cli import app

COMMANDS = ("analyze", "flows", "ciphers", "detectors", "suites", "doctor", "schema")


def test_analyze_is_registered_once(cli_runner) -> None:
    assert cli_runner.invoke(app, ["analyze", "--help"]).exit_code == 0
    assert cli_runner.invoke(app, ["analyze-cmd", "--help"]).exit_code == 2


def test_every_command_is_registered(cli_runner) -> None:
    for name in COMMANDS:
        assert cli_runner.invoke(app, [name, "--help"]).exit_code == 0, name


def test_module_entry_point_still_works() -> None:
    """The Makefile runs `python -m pcap_doctor.cli ...`."""
    out = subprocess.run([sys.executable, "-m", "pcap_doctor.cli", "--help"], capture_output=True, text=True)
    assert out.returncode == 0
    assert "analyze" in out.stdout
