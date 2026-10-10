"""Long text screens scroll: Show findings report, Show fix prompt, the workflow, the launch preview (issue #104)."""

from __future__ import annotations

from rich.console import Console

from pcap_doctor.cli._browse import DOWN, END, ENTER, HOME, PGDN, PGUP, UP, Browser, split_keys
from pcap_doctor.models import Report
from test_browse import _browser, _finding, _press, _report


def _long_report() -> Report:
    return _report(*[_finding("DNS_CLEARTEXT", "medium", f"s{i}", title=f"DNS in cleartext number {i}") for i in range(12)])


def _screen(browser: Browser, height: int = 30, width: int = 90) -> str:
    console = Console(record=True, width=width, height=height, force_terminal=False)
    console.print(browser.render(height, width))
    text = console.export_text()
    assert len(text.rstrip("\n").splitlines()) <= height, "the screen must fit, footer included"
    return text


def _show_report(report: Report | None = None) -> Browser:
    browser, _, _ = _browser(report or _long_report(), agents=())
    _press(browser, DOWN, DOWN, ENTER, DOWN, ENTER)  # home → Hand off → Show findings report
    assert browser.screen.what == "findings report"
    return browser


def test_split_keys_knows_paging_keys() -> None:
    assert split_keys("\x1b[5~\x1b[6~\x1b[H\x1b[4~\x1bOFG g") == [PGUP, PGDN, HOME, END, END, END, " ", "g"]


def test_show_findings_report_scrolls_line_page_and_ends() -> None:
    browser = _show_report()
    top = _screen(browser)
    assert "# Security findings: x.pcap" in top and "lines 1–" in top and "· top" in top
    assert top.rstrip().endswith("c copy · s save · esc back · q quit")
    _press(browser, DOWN)
    assert "# Security findings" not in _screen(browser) and "lines 2–" in _screen(browser)
    _press(browser, PGDN)
    assert f"lines {2 + browser._page}–" in _screen(browser)
    _press(browser, END)
    end = _screen(browser)
    assert "not proof of safety" in end and "· end" in end
    _press(browser, DOWN, DOWN)  # already at the end: stays
    assert _screen(browser) == end
    _press(browser, "g")
    assert "lines 1–" in _screen(browser)
    _press(browser, UP)  # already at the top: stays
    assert "lines 1–" in _screen(browser)


def test_short_text_shows_no_position_and_long_lines_wrap() -> None:
    browser = _show_report(_report(_finding("DNS_CLEARTEXT", "medium", "a", title="x" * 300)))
    text = _screen(browser, height=60, width=80)
    assert "lines 1–" not in text  # fits: nothing to scroll
    assert all(len(line) <= 80 for line in text.splitlines())


def test_confirm_preview_scrolls_with_paging_keys_and_arrows_still_choose() -> None:
    browser, _, _ = _browser(_long_report())
    _press(browser, DOWN, DOWN, ENTER, ENTER)  # Hand off → Claude Code: the prompt preview
    assert browser.screen.name == "confirm"
    _screen(browser)
    _press(browser, DOWN)
    assert browser.screen.cursor == 1 and browser.screen.offset == 0  # arrows move the choice
    _press(browser, PGDN)
    assert browser.screen.offset > 0 and "lines 1–" not in _screen(browser)
    assert "PgUp/PgDn scroll" in _screen(browser)
