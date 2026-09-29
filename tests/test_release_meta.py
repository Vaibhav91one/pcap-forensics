"""The release workflow publishes to PyPI with trusted publishing, only for a matching tag (issue #50)."""

from __future__ import annotations

from pathlib import Path

RELEASE = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"


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
