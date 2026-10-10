"""--firmware correlation: a server key that ships in the image is flagged, leaking no secret (#121)."""

from __future__ import annotations

import json

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli import app

# rsa_kx.key is the server private key for rsa_kx.pcap, so a firmware tree that contains it is
# exactly the white-box case: the key protecting the wire session ships in the image.
KEY = FIXTURES / "rsa_kx.key"
PCAP = FIXTURES / "rsa_kx.pcap"


def _findings(out_dir) -> list[dict]:
    return json.loads((out_dir / "report.json").read_text())["findings"]


def _firmware_tree(tmp_path):
    fw = tmp_path / "fw"
    (fw / "etc").mkdir(parents=True)
    (fw / "etc" / "server.key").write_bytes(KEY.read_bytes())
    return fw


@requires_tshark
def test_key_in_firmware_fires_critical(cli_runner, tmp_path, cache_dir) -> None:
    fw = _firmware_tree(tmp_path)
    r = cli_runner.invoke(app, ["analyze", str(PCAP), "-o", str(tmp_path / "r"), "-q",
                                "--no-handoff", "--firmware", str(fw)])
    assert r.exit_code == 0
    hits = [f for f in _findings(tmp_path / "r") if f["code"] == "TLS_KEY_IN_FIRMWARE"]
    assert len(hits) == 1
    hit = hits[0]
    assert hit["severity"] == "critical"
    # evidence carries the non-secret fingerprint and the firmware-relative path, not host paths
    fields = {e["field"]: e["value"] for e in hit["evidence"]}
    assert fields["firmware.private_key"] == "etc/server.key"
    assert len(fields["x509af.subjectPublicKey[spki_sha256]"]) == 16


@requires_tshark
def test_no_firmware_no_finding(cli_runner, tmp_path, cache_dir) -> None:
    r = cli_runner.invoke(app, ["analyze", str(PCAP), "-o", str(tmp_path / "r"), "-q", "--no-handoff"])
    assert r.exit_code == 0
    assert not any(f["code"] == "TLS_KEY_IN_FIRMWARE" for f in _findings(tmp_path / "r"))


@requires_tshark
def test_unrelated_firmware_key_does_not_fire(cli_runner, tmp_path, cache_dir) -> None:
    import subprocess

    from pcap_doctor.certificates import openssl_path

    if openssl_path() is None:
        return
    fw = tmp_path / "fw"
    fw.mkdir()
    subprocess.run([openssl_path(), "genrsa", "-out", str(fw / "other.key"), "2048"],
                   capture_output=True, check=True)
    r = cli_runner.invoke(app, ["analyze", str(PCAP), "-o", str(tmp_path / "r"), "-q",
                                "--no-handoff", "--firmware", str(fw)])
    assert r.exit_code == 0
    assert not any(f["code"] == "TLS_KEY_IN_FIRMWARE" for f in _findings(tmp_path / "r"))


@requires_tshark
def test_firmware_key_material_never_reaches_an_artifact(cli_runner, tmp_path, cache_dir) -> None:
    fw = _firmware_tree(tmp_path)
    out = tmp_path / "r"
    r = cli_runner.invoke(app, ["analyze", str(PCAP), "-o", str(out), "-q", "--no-handoff",
                                "--firmware", str(fw), "--json-out", str(tmp_path / "env.json"),
                                "--sarif", str(tmp_path / "out.sarif")])
    assert r.exit_code == 0
    blob = "".join(p.read_text(errors="ignore") for p in out.glob("*")) \
        + (tmp_path / "env.json").read_text() + (tmp_path / "out.sarif").read_text()
    assert "PRIVATE KEY" not in blob  # no key bytes
    assert str(fw) not in blob  # no absolute host path; only the firmware-relative path is evidence
    assert "TLS_KEY_IN_FIRMWARE" in blob  # but the finding itself is reported


def test_rule_is_catalogued() -> None:
    from pathlib import Path

    from pcap_doctor.rules import RULES

    assert "TLS_KEY_IN_FIRMWARE" in RULES
    doc = Path(__file__).parent.parent / "src/pcap_doctor/rule_docs/TLS_KEY_IN_FIRMWARE.md"
    assert doc.exists()
