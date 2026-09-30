"""`keys scan` inventories key material in an extracted firmware tree and flags the dangerous parts (#117)."""

from __future__ import annotations

import json
import subprocess

import pytest

from pcapforensics.certificates import openssl_path
from pcapforensics.cli import app
from pcapforensics.cli.keys import scan

needs_openssl = pytest.mark.skipif(openssl_path() is None, reason="needs openssl")


def _make_key_and_cert(dir_path, name, bits, *, self_signed=True):
    key = dir_path / f"{name}.key"
    cert = dir_path / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-nodes", "-days", "3650",
                    "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True)
    return key, cert


@needs_openssl
def test_scan_classifies_and_flags(tmp_path):
    fw = tmp_path / "fs"
    (fw / "etc").mkdir(parents=True)
    _make_key_and_cert(fw / "etc", "weakca", 512)          # weak + we hold its key
    _make_key_and_cert(fw / "etc", "device", 2048)         # normal
    entries = scan(fw)
    by = {e.path.rsplit("/", 1)[-1]: e for e in entries}
    assert by["weakca.key"].kind == "private-key" and by["weakca.key"].bits == 512
    assert "weak-key-512bit" in by["weakca.key"].flags
    assert "private-key-for-a-shipped-cert" in by["weakca.key"].flags  # SPKI matches weakca.crt
    assert "private-key-present" in by["weakca.crt"].flags
    assert by["device.key"].bits == 2048 and not any("weak" in f for f in by["device.key"].flags)
    # private-key bytes never surface in an entry
    assert all("PRIVATE KEY" not in json.dumps(e.__dict__) for e in entries)


@needs_openssl
def test_cli_json_and_out_dir(cli_runner, tmp_path):
    fw = tmp_path / "fs"
    fw.mkdir()
    _make_key_and_cert(fw, "srv", 1024)
    result = cli_runner.invoke(app, ["keys", "scan", str(fw), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["root"].endswith("fs") and any("weak-key-1024bit" in e["flags"] for e in data["entries"])
    assert "PRIVATE KEY" not in result.output  # no key bytes in the JSON

    out = tmp_path / "keys.d"
    assert cli_runner.invoke(app, ["keys", "scan", str(fw), "--out", str(out)]).exit_code == 0
    written = list(out.glob("*.pem"))
    assert len(written) == 1 and "PRIVATE KEY" in written[0].read_text()  # normalized for --keys-from


def test_scan_needs_a_directory(cli_runner, tmp_path):
    assert cli_runner.invoke(app, ["keys", "scan", str(tmp_path / "nope")]).exit_code == 2
