"""Project config: disable, [severity] re-rating and [[allow]] entries, all noted in the report (issue #57)."""

from __future__ import annotations

import json
import re

import pytest

from conftest import FIXTURES, requires_tshark
from pcapforensics.cli import app
from pcapforensics.config import Config, ConfigError, apply, load, parse
from pcapforensics.models import Finding


def _finding(code: str, subject: str = "10.0.0.1") -> Finding:
    return Finding.make(
        detector="d1.tls_cipher", code=code, title=code, severity="high", confidence="high",
        category="crypto", summary="", scope=f"{code}{subject}", subjects=[subject], flow_key=f"tcp:{subject}:1<->9.9.9.9:443",
    )


def test_disable_severity_and_allow_are_applied_and_noted() -> None:
    config = parse(
        {
            "disable": ["DNS_CLEARTEXT"],
            "severity": {"TLS_CERT_EXPIRING": "low"},
            "allow": [{"code": "TLS_CIPHER_*", "subject": "10.0.0.2*", "reason": "legacy box"}],
        },
        "cfg",
    )
    findings = [
        _finding("DNS_CLEARTEXT"),
        _finding("TLS_CERT_EXPIRING"),
        _finding("TLS_CIPHER_WEAK", "10.0.0.20"),
        _finding("TLS_CIPHER_WEAK", "10.0.0.30"),
    ]
    kept, notes = apply(findings, config)
    assert [(f.code, f.subjects[0], f.severity) for f in kept] == [
        ("TLS_CERT_EXPIRING", "10.0.0.1", "low"),
        ("TLS_CIPHER_WEAK", "10.0.0.30", "high"),
    ]
    assert kept[0].id == findings[1].id  # re-rating keeps the stable id
    assert notes == [
        "[config] re-rated 1 finding(s) by [severity] in cfg",
        "[config] disabled 1 finding(s) in cfg: DNS_CLEARTEXT x1",
        "[config] allowed 1 finding(s) in cfg: legacy box",
    ]


def test_allow_by_flow_key() -> None:
    config = parse({"allow": [{"flow_key": "tcp:10.0.0.1:*", "reason": "lab"}]}, "cfg")
    assert apply([_finding("TLS_CIPHER_WEAK"), _finding("TLS_CIPHER_WEAK", "10.0.0.9")], config)[0][0].subjects == ["10.0.0.9"]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"disabled": []}, "unknown key(s) disabled"),
        ({"disable": ["NOPE"]}, "unknown code(s) NOPE"),
        ({"severity": {"TLS_CIPHER_WEAK": "urgent"}}, "invalid value(s) TLS_CIPHER_WEAK=urgent"),
        ({"allow": [{"code": "TLS_CIPHER_WEAK"}]}, "reason is required"),
        ({"allow": [{"reason": "x"}]}, "needs at least one of code, subject, flow_key"),
        ({"allow": [{"reason": "x", "code": "A", "host": "h"}]}, "unknown key(s) host"),
    ],
)
def test_invalid_config_is_rejected(data: dict, message: str) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        parse(data, "cfg")


def test_discovery_prefers_pcap_doctor_toml(tmp_path) -> None:
    assert load(cwd=tmp_path) == Config()
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert load(cwd=tmp_path) == Config()
    (tmp_path / "pyproject.toml").write_text('[tool.pcap-doctor]\ndisable = ["DNS_CLEARTEXT"]\n')
    assert load(cwd=tmp_path).disable == {"DNS_CLEARTEXT"}
    (tmp_path / "pcap-doctor.toml").write_text('disable = ["TLS_CIPHER_WEAK"]\n')
    assert load(cwd=tmp_path).disable == {"TLS_CIPHER_WEAK"}
    (tmp_path / "other.toml").write_text('[project]\nname = "x"\n')
    with pytest.raises(ConfigError, match="unknown key"):
        load(tmp_path / "other.toml")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    with pytest.raises(ConfigError, match=re.escape("no [tool.pcap-doctor] table")):
        load(tmp_path / "pyproject.toml")


def test_unknown_code_in_config_exits_2_before_tshark(cli_runner, tmp_path, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("analyze must not run")

    monkeypatch.setattr("pcapforensics.cli.analyze.analyze", boom)
    cfg = tmp_path / "pcap-doctor.toml"
    cfg.write_text('disable = ["NOPE"]\n')
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "weak_tls.pcap"), "--config", str(cfg)])
    assert result.exit_code == 2
    assert "NOPE" in result.output


@requires_tshark
def test_disabled_code_is_gone_from_the_report_and_noted(cli_runner, tmp_path, cache_dir) -> None:
    cfg = tmp_path / "pcap-doctor.toml"
    cfg.write_text('disable = ["TLS_CIPHER_WEAK"]\n')
    args = ["analyze", str(FIXTURES / "weak_tls.pcap"), "-o", str(tmp_path / "r"), "-q", "--config", str(cfg)]
    assert cli_runner.invoke(app, args).exit_code == 0
    report = json.loads((tmp_path / "r" / "report.json").read_text())
    assert "TLS_CIPHER_WEAK" not in {f["code"] for f in report["findings"]}
    assert f"[config] disabled 1 finding(s) in {cfg}: TLS_CIPHER_WEAK x1" in report["notes"]


def test_config_is_found_from_a_subfolder_up_to_the_repo_root(tmp_path) -> None:
    """Running from repo/captures/lab must not silently ignore repo/pcap-doctor.toml (#106)."""
    outside = tmp_path
    repo = tmp_path / "repo"
    deep = repo / "captures" / "lab"
    deep.mkdir(parents=True)
    (repo / ".git").mkdir()
    (outside / "pcap-doctor.toml").write_text('disable = ["SYN_SCAN_SHAPE"]\n')  # above the repo: never used
    assert load(cwd=deep) == Config()
    (repo / "pcap-doctor.toml").write_text('disable = ["DNS_CLEARTEXT"]\n')
    found = load(cwd=deep)
    assert found.disable == {"DNS_CLEARTEXT"} and found.source == str(repo / "pcap-doctor.toml")
    (repo / "captures" / "pyproject.toml").write_text('[project]\nname = "x"\n')  # no table: keep looking
    assert load(cwd=deep).disable == {"DNS_CLEARTEXT"}
    (repo / "captures" / "pcap-doctor.toml").write_text('disable = ["TLS_CIPHER_WEAK"]\n')  # nearer wins
    assert load(cwd=deep).disable == {"TLS_CIPHER_WEAK"}


def test_cli_uses_the_repo_config_from_a_subfolder(cli_runner, tmp_path, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise AssertionError("analyze must not run")

    repo = tmp_path / "repo"
    (repo / "captures").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "pcap-doctor.toml").write_text('disable = ["NOPE"]\n')  # invalid: proves the file was read
    monkeypatch.chdir(repo / "captures")
    monkeypatch.setattr("pcapforensics.cli.analyze.analyze", boom)
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "weak_tls.pcap")])
    assert result.exit_code == 2 and "NOPE" in result.output
