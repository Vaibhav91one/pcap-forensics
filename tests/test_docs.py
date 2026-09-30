"""The docs stay true: links and anchors resolve, documented commands exist, versions agree (issue #65)."""

from __future__ import annotations

import json
import re
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest
import typer

from pcapforensics import TOOL_VERSION
from pcapforensics.cli import app

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "AGENTS.md", ROOT / "CHANGELOG.md",
        *sorted((ROOT / "docs").glob("*.md"))]
LINK = re.compile(r"\]\(([^)\s]+)\)")


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)
    return {_slug(m) for m in re.findall(r"^#{1,6} (.+)$", text, flags=re.M)}


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_and_anchors_resolve(doc: Path) -> None:
    text = re.sub(r"```.*?```", "", doc.read_text(encoding="utf-8"), flags=re.S)
    broken = []
    for target in LINK.findall(text):
        if re.match(r"[a-z]+:", target):
            continue  # http(s), mailto: not checked offline
        path, _, anchor = target.partition("#")
        dest = (doc.parent / path).resolve() if path else doc
        if not dest.exists() or (anchor and dest.suffix == ".md" and anchor not in _anchors(dest)):
            broken.append(target)
    assert broken == []


def _commands(typer_app: typer.Typer, prefix: str = "") -> set[str]:
    names: set[str] = set()
    for info in typer_app.registered_commands:
        names.add(prefix + (info.name or info.callback.__name__.replace("_", "-")))
    for group in typer_app.registered_groups:
        names.add(prefix + str(group.name))
        names |= _commands(group.typer_instance, f"{prefix}{group.name} ")
    return names


def test_every_documented_command_exists() -> None:
    real = _commands(app)
    documented = set()
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        code = re.findall(r"```.*?```", text, flags=re.S) + re.findall(r"`([^`\n]+)`", text)
        for snippet in code:
            for match in re.finditer(r"^\s*(?:pcap-doctor|pf) ([a-z]+(?: (?:list|explain|install))?)\b", snippet, flags=re.M):
                documented.add(match.group(1))
    unknown = sorted(c for c in documented if c not in real and c.split()[0] not in real)
    assert unknown == [], f"documented but not a command: {unknown}"
    assert {"analyze", "why", "rules list", "rules explain", "install", "ci install", "watch"} <= documented


def test_versions_agree() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    npm = json.loads((ROOT / "npm" / "package.json").read_text())["version"]
    assert pyproject == npm == version("pcap-doctor") == TOOL_VERSION
    assert f"Vaibhav91one/pcap-forensics@v{pyproject}" in (ROOT / "README.md").read_text()
    assert f"## [{pyproject}]" in (ROOT / "CHANGELOG.md").read_text()


REPO_LINK = re.compile(
    r"https://(?:github\.com/Vaibhav91one/pcap-forensics/(?:blob|tree)/main|"
    r"raw\.githubusercontent\.com/Vaibhav91one/pcap-forensics/main)/([^)\"#\s>]+)"
)


@pytest.mark.parametrize("doc", [ROOT / "README.md", ROOT / "npm" / "README.md"], ids=lambda p: str(p.relative_to(ROOT)))
def test_readmes_shown_on_pypi_and_npm_use_absolute_links_that_exist(doc: Path) -> None:
    """PyPI and npm show these files away from the repo: a relative link or image breaks there (#105)."""
    text = re.sub(r"```.*?```", "", doc.read_text(encoding="utf-8"), flags=re.S)
    relative = [t for t in LINK.findall(text) + re.findall(r'(?:src|srcset)="([^"]+)"', text)
                if not re.match(r"[a-z]+:|#", t)]
    assert relative == []
    missing = [path for path in REPO_LINK.findall(text) if not (ROOT / path).exists()]
    assert missing == []


def test_package_metadata_links_the_project() -> None:
    urls = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["urls"]
    assert {"Homepage", "Repository", "Issues", "Changelog"} <= set(urls)
    package = json.loads((ROOT / "npm" / "package.json").read_text())
    assert package["repository"]["url"].endswith("Vaibhav91one/pcap-forensics.git")
