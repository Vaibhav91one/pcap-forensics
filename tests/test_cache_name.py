"""The tshark cache setting uses the pcap-doctor name; the old one keeps working (issue #112)."""

from __future__ import annotations

from pathlib import Path

from pcapforensics.tshark import cache_dir


def test_cache_dir_precedence(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("PCAP_DOCTOR_CACHE", raising=False)
    monkeypatch.delenv("PCAP_FORENSICS_CACHE", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert cache_dir() == tmp_path / ".cache" / "pcap-doctor"
    monkeypatch.setenv("PCAP_FORENSICS_CACHE", str(tmp_path / "old"))
    assert cache_dir() == tmp_path / "old"  # the old name is still honoured
    monkeypatch.setenv("PCAP_DOCTOR_CACHE", str(tmp_path / "new"))
    assert cache_dir() == tmp_path / "new"  # the new name wins
    assert (tmp_path / "new").is_dir()
