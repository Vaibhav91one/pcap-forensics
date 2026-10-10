"""The tool is published and run as pcap-doctor; `pf` stays as an alias (issue #46)."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pcap_doctor.cli import app

PYPROJECT = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())


def test_distribution_is_pcap_doctor_with_both_commands() -> None:
    assert PYPROJECT["project"]["name"] == "pcap-doctor"
    scripts = PYPROJECT["project"]["scripts"]
    assert scripts["pcap-doctor"] == scripts["pf"] == "pcap_doctor.cli:app"


def test_version_flag_prints_the_package_version(cli_runner) -> None:
    result = cli_runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"pcap-doctor {PYPROJECT['project']['version']}"


def test_no_arguments_still_shows_help(cli_runner) -> None:
    result = cli_runner.invoke(app, [])
    assert "analyze" in result.output
