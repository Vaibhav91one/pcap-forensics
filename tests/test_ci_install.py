"""`ci install` writes a GitHub workflow using the repo's composite action, which gates new findings (issue #63)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

from conftest import FIXTURES, requires_tshark
from pcapforensics.cli import app

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pcap-doctor-action.sh"


def test_install_writes_the_workflow_and_keeps_edits_unless_forced(cli_runner, tmp_path) -> None:
    assert cli_runner.invoke(app, ["ci", "install", "--dir", str(tmp_path)]).exit_code == 0
    path = tmp_path / ".github" / "workflows" / "pcap-doctor.yml"
    text = path.read_text()
    assert "pull-requests: write" in text and "security-events: write" in text
    assert f"uses: doctor-labs/pcap-doctor@v{version('pcap-doctor')}" in text
    assert 'captures: "**/*.pcap **/*.pcapng"' in text and "fail-on: high" in text
    assert "__" not in text  # every placeholder filled

    assert cli_runner.invoke(app, ["ci", "install", "--dir", str(tmp_path)]).exit_code == 0  # same content: fine
    path.write_text(text + "# local edit\n")
    assert cli_runner.invoke(app, ["ci", "install", "--dir", str(tmp_path)]).exit_code == 1
    assert path.read_text().endswith("# local edit\n")
    args = ["ci", "install", "--dir", str(tmp_path), "--force", "--captures", "caps/*.pcap", "--fail-on", "medium", "--ref", "main"]
    assert cli_runner.invoke(app, args).exit_code == 0
    text = path.read_text()
    assert "@main" in text and 'captures: "caps/*.pcap"' in text and "fail-on: medium" in text


@pytest.mark.parametrize(
    ("args", "message"),
    [(["--fail-on", "urgent"], "--fail-on: unknown value urgent"), (["--captures", 'a"b'], "--captures:"), (["--captures", " "], "--captures:")],
)
def test_bad_options_exit_2(cli_runner, tmp_path, args: list[str], message: str) -> None:
    result = cli_runner.invoke(app, ["ci", "install", "--dir", str(tmp_path), *args])
    assert result.exit_code == 2 and message in result.output
    assert not (tmp_path / ".github").exists()


def test_action_runs_the_script_that_uses_baseline_and_sarif() -> None:
    action = (ROOT / "action.yml").read_text()
    assert "using: composite" in action and "$GITHUB_ACTION_PATH/scripts/pcap-doctor-action.sh" in action
    assert os.access(SCRIPT, os.X_OK)
    script = SCRIPT.read_text()
    assert "--baseline" in script and "--sarif" in script and "--no-handoff" in script


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


def _action(repo: Path, base: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "CAPTURES": "caps/*.pcap", "BASE_SHA": base, "OUT": str(repo / "out"),
           "PCAP_DOCTOR": f"{sys.executable} -m pcapforensics.cli", "GITHUB_STEP_SUMMARY": "", "GITHUB_OUTPUT": ""}
    return subprocess.run(["bash", str(SCRIPT)], cwd=repo, env=env, capture_output=True, text=True, check=False)


@requires_tshark
@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_action_script_gates_only_findings_new_since_the_base(tmp_path, cache_dir) -> None:
    repo = tmp_path / "repo"
    (repo / "caps").mkdir(parents=True)
    _git(repo, "init", "-q")
    shutil.copy(FIXTURES / "sip_rtp.pcap", repo / "caps" / "a.pcap")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD").strip()
    shutil.copy(FIXTURES / "weak_tls.pcap", repo / "caps" / "b.pcap")  # new capture: all its findings are new

    result = _action(repo, base)
    assert result.returncode == 1, result.stderr
    assert "| `caps/a.pcap` | 0 | 3 |" in result.stdout
    assert "| `caps/b.pcap` | 4 :x: | 4 |" in result.stdout
    sarif = json.loads((repo / "out" / "pcap-doctor.sarif").read_text())
    assert len(sarif["runs"]) == 1 and len(sarif["runs"][0]["results"]) == 4

    (repo / "caps" / "b.pcap").unlink()
    assert _action(repo, base).returncode == 0
