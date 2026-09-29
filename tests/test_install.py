"""`install` writes agent guides idempotently and never clobbers user edits without --force (issue #62)."""

from __future__ import annotations

from pcapforensics.cli import app
from pcapforensics.cli.install import BEGIN, END, guide

SKILL = ".claude/skills/pcap-doctor/SKILL.md"
RULE = ".cursor/rules/pcap-doctor.mdc"


def test_installs_all_three_agents(cli_runner, tmp_path) -> None:
    result = cli_runner.invoke(app, ["install", "--dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    skill = (tmp_path / SKILL).read_text()
    assert skill.startswith("---\nname: pcap-doctor\ndescription: ")
    assert (tmp_path / RULE).read_text().startswith("---\ndescription: ")
    assert guide() in skill
    assert BEGIN in (tmp_path / "AGENTS.md").read_text()


def test_installing_twice_keeps_one_block_and_user_text(cli_runner, tmp_path) -> None:
    (tmp_path / "AGENTS.md").write_text("# My project\n\nKeep this.\n")
    for _ in range(2):
        assert cli_runner.invoke(app, ["install", "--dir", str(tmp_path)]).exit_code == 0
    text = (tmp_path / "AGENTS.md").read_text()
    assert text.count(BEGIN) == 1 and text.count(END) == 1
    assert text.startswith("# My project\n\nKeep this.\n\n")


def test_edited_file_is_kept_unless_forced(cli_runner, tmp_path) -> None:
    rule = tmp_path / RULE
    rule.parent.mkdir(parents=True)
    rule.write_text("my own rule\n")
    result = cli_runner.invoke(app, ["install", "--agent", "cursor", "--dir", str(tmp_path)])
    assert result.exit_code == 1
    assert rule.read_text() == "my own rule\n"
    assert cli_runner.invoke(app, ["install", "--agent", "cursor", "--force", "--dir", str(tmp_path)]).exit_code == 0
    assert guide() in rule.read_text()


def test_only_the_chosen_agent_is_installed(cli_runner, tmp_path) -> None:
    assert cli_runner.invoke(app, ["install", "--agent", "claude", "--dir", str(tmp_path)]).exit_code == 0
    assert (tmp_path / SKILL).exists()
    assert not (tmp_path / RULE).exists() and not (tmp_path / "AGENTS.md").exists()


def test_unknown_agent_exits_2(cli_runner, tmp_path) -> None:
    result = cli_runner.invoke(app, ["install", "--agent", "copilot", "--dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "valid: claude, cursor, codex" in result.output
