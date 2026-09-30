"""The release workflow publishes to PyPI with trusted publishing, then npm, only for a matching tag (#50, #51)."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def test_release_runs_only_on_version_tags() -> None:
    text = RELEASE.read_text()
    assert 'tags: ["v*"]' in text
    assert "pull_request" not in text


def test_release_checks_the_tag_against_the_package_version() -> None:
    text = RELEASE.read_text()
    assert "GITHUB_REF_NAME" in text
    assert "['project']['version']" in text


def test_release_uses_trusted_publishing_without_a_token() -> None:
    text = RELEASE.read_text()
    assert "id-token: write" in text
    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "password:" not in text
    assert "PYPI_API_TOKEN" not in text


def test_npm_launcher_version_matches_the_python_package() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    package = json.loads((ROOT / "npm" / "package.json").read_text())
    assert package["name"] == pyproject["name"] == "pcap-doctor"
    assert package["version"] == pyproject["version"]
    assert package["bin"] == {"pcap-doctor": "bin/pcap-doctor.js"}


def test_npm_publishes_after_pypi_with_trusted_publishing() -> None:
    text = RELEASE.read_text()
    npm_job = text.split("\n  npm:\n", 1)[1]
    assert "needs: pypi" in npm_job
    assert "id-token: write" in npm_job and "npm install -g npm@latest" in npm_job
    assert "npm publish --access public" in npm_job
    assert "NPM_TOKEN" not in text and "NODE_AUTH_TOKEN" not in text  # no npm token exists (#93)
    assert "E404" in npm_job and "already on npm" in npm_job  # first publish is manual; reruns are safe
    assert "npm/package.json" in text.split("\n  pypi:\n", 1)[0]
