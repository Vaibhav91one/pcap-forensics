"""`rules list` shows the whole catalog and `rules explain` renders a rule doc (issue #61)."""

from __future__ import annotations

from pcapforensics.cli import app
from pcapforensics.rules import RULES


def _run(cli_runner, *args: str):
    return cli_runner.invoke(app, ["rules", *args], env={"COLUMNS": "200"})


def test_list_includes_every_code(cli_runner) -> None:
    result = _run(cli_runner, "list")
    assert result.exit_code == 0
    assert all(code in result.output for code in RULES)


def test_list_filters_by_category(cli_runner) -> None:
    result = _run(cli_runner, "list", "--category", "DNS")
    assert result.exit_code == 0
    shown = {code for code in RULES if code in result.output}
    assert shown == {r.code for r in RULES.values() if r.category == "DNS"}


def test_list_rejects_unknown_category(cli_runner) -> None:
    assert _run(cli_runner, "list", "--category", "Nope").exit_code == 2


def test_explain_renders_the_rule_doc(cli_runner) -> None:
    result = _run(cli_runner, "explain", "tls_version_deprecated")
    assert result.exit_code == 0
    for heading in ("What it means", "Why it matters", "How to fix", "How to verify"):
        assert heading in result.output


def test_explain_unknown_code_suggests_close_matches(cli_runner) -> None:
    result = _run(cli_runner, "explain", "TLS_VERSION_DEPRECATD")
    assert result.exit_code == 2
    assert "did you mean TLS_VERSION_DEPRECATED" in result.output
