"""AI handoff: finding menu -> prompt preview -> launch / copy / print; guidance inside agents (issue #59)."""

from __future__ import annotations

from rich.console import Console

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.handoff import (
    AGENT_ENV,
    AGENTS,
    detect_agents,
    in_agent,
    launch_argv,
    menu,
    offer,
    safe_mode,
)
from pcap_doctor.models import CaptureInfo, Finding, Report, Stats
from pcap_doctor.prompts import FENCE_LABEL

CLAUDE, CODEX, CURSOR = AGENTS
NO_AGENT_ENV: dict[str, str | None] = {name: None for name in AGENT_ENV}


def _report() -> Report:
    findings = [
        Finding.make(
            detector="d1.tls_cipher", code=code, title=f"{code} title", severity=sev, confidence="high",
            category="crypto", summary="s", scope=code,
        )
        for code, sev in (("TLS_CERT_EXPIRING", "low"), ("TLS_CIPHER_WEAK", "high"))
    ]
    capture = CaptureInfo(
        path="/c/x.pcap", name="x.pcap", sha256="0" * 64, size_bytes=1, packets=1, bytes=1,
        first_seen=0.0, last_seen=0.0, duration=0.0,
    )
    return Report(generated_at="now", capture=capture, stats=Stats(), flows=[], tls_sessions=[], findings=findings)


def _console() -> Console:
    return Console(record=True, width=200, force_terminal=False)


def _asker(*answers: str):
    queue = list(answers)
    asked: list[tuple[str, list[str]]] = []

    def ask(question: str, choices: list[str]) -> str:
        asked.append((question, choices))
        return queue.pop(0)

    return ask, asked


def _no_menu(*_a, **_k) -> str:
    raise AssertionError("the menu must not be shown")


def test_launch_argv_per_agent_and_safe_mode() -> None:
    assert launch_argv(CLAUDE, "P", safe=False) == ["claude", "--dangerously-skip-permissions", "P"]
    assert launch_argv(CODEX, "P", safe=False) == ["codex", "--dangerously-bypass-approvals-and-sandbox", "P"]
    assert launch_argv(CURSOR, "P", safe=False) == ["cursor-agent", "--force", "P"]
    assert [launch_argv(a, "P", safe=True) for a in AGENTS] == [["claude", "P"], ["codex", "P"], ["cursor-agent", "P"]]
    assert safe_mode(False, {"PCAP_DOCTOR_HANDOFF_SAFE": "1"}) and safe_mode(True, {}) and not safe_mode(False, {})


def test_detection_of_agents_clipboard_and_agent_shells() -> None:
    assert detect_agents(lambda b: b if b in ("codex", "cursor-agent") else None) == [CODEX, CURSOR]
    assert not in_agent({})
    assert all(in_agent({name: "1"}) for name in AGENT_ENV)


def test_inside_an_agent_prints_guidance_and_never_shows_the_menu() -> None:
    console = _console()
    offer(console, _report(), safe=False, env={"CLAUDECODE": "1"}, interactive=True, ask=_no_menu)
    text = console.export_text()
    assert "Agent guidance" in text
    assert text.index("TLS_CIPHER_WEAK") < text.index("TLS_CERT_EXPIRING")  # worst first
    assert f"pcap-doctor why {_report().findings[1].id} --prompt" in text


def test_no_menu_without_a_terminal_or_in_ci() -> None:
    for env, interactive in (({}, False), ({"CI": "true"}, True)):
        console = _console()
        offer(console, _report(), safe=False, env=env, interactive=interactive, ask=_no_menu)
        assert console.export_text() == ""


def test_menu_previews_the_prompt_then_launches_the_chosen_agent() -> None:
    console = _console()
    ask, asked = _asker("1", "2")
    launched: list[list[str]] = []
    menu(console, _report(), safe=False, ask=ask, run=lambda argv: launched.append(argv) or 0,
         which=lambda b: b if b in ("claude", "codex") else None)
    (argv,) = launched
    assert argv[:2] == ["codex", "--dangerously-bypass-approvals-and-sandbox"]
    assert "TLS_CIPHER_WEAK" in argv[2] and FENCE_LABEL in argv[2]  # finding 1 is the worst one
    assert asked[1][1] == ["1", "2", "c", "p"]  # copy always has a fallback (#101)
    text = console.export_text()
    assert "  1. high     TLS_CIPHER_WEAK  TLS_CIPHER_WEAK title" in text
    assert text.index("prompt preview") < text.index("launch Codex")
    assert "skips its approval prompts" in text


def test_menu_skip_copy_and_safe_launch() -> None:
    ask, _ = _asker("q")
    menu(_console(), _report(), safe=False, ask=ask, run=_no_menu, which=lambda b: b)

    copied: list[str] = []
    ask, _ = _asker("2", "c")
    menu(_console(), _report(), safe=False, ask=ask, run=_no_menu,
         which=lambda b: None, copy=lambda text: copied.append(text) or "pbcopy")
    assert "TLS_CERT_EXPIRING" in copied[0]

    launched: list[list[str]] = []
    ask, _ = _asker("1", "1")
    console = _console()
    menu(console, _report(), safe=True, ask=ask, run=lambda argv: launched.append(argv) or 0, which=lambda b: b)
    assert launched[0][0] == "claude" and len(launched[0]) == 2
    assert "skips its approval prompts" not in console.export_text()


@requires_tshark
def test_cli_prints_guidance_inside_an_agent_unless_no_handoff(cli_runner, tmp_path, cache_dir) -> None:
    args = ["analyze", str(FIXTURES / "weak_tls.pcap"), "-o", str(tmp_path / "r")]
    inside = cli_runner.invoke(app, args, env={**NO_AGENT_ENV, "PCAP_DOCTOR_AGENT": "1"})
    assert "Agent guidance" in inside.output and "--prompt" in inside.output
    assert "Agent guidance" not in cli_runner.invoke(app, [*args, "--no-handoff"], env={**NO_AGENT_ENV, "PCAP_DOCTOR_AGENT": "1"}).output
    assert "Agent guidance" not in cli_runner.invoke(app, args, env=NO_AGENT_ENV).output
