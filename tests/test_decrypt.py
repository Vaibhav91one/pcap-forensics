"""`analyze` decrypts the operator's own capture with supplied key material, leaking no secret (#115)."""

from __future__ import annotations

import json

from conftest import FIXTURES, requires_tshark
from pcap_doctor.cli import app
from pcap_doctor.index import IndexBuilder
from pcap_doctor.keymaterial import KeyMaterial
from pcap_doctor.tshark import TsharkRunner

KEY = "rsa_kx.key"  # the server RSA key for rsa_kx.pcap (a static-RSA TLS session carrying HTTP)


def _notes(out_dir) -> list[str]:
    return json.loads((out_dir / "report.json").read_text())["notes"]


@requires_tshark
def test_without_a_key_nothing_is_decrypted(cli_runner, tmp_path, cache_dir) -> None:
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "rsa_kx.pcap"), "-o", str(tmp_path / "r"), "-q"])
    assert result.exit_code == 0
    assert not any("decrypt" in n for n in _notes(tmp_path / "r"))


@requires_tshark
def test_with_the_key_inner_traffic_is_read_and_noted(cache_dir) -> None:
    km = KeyMaterial(tls_keys=((FIXTURES / KEY).resolve(),))
    plain = IndexBuilder(TsharkRunner(FIXTURES / "rsa_kx.pcap", use_cache=False)).build()
    keyed = IndexBuilder(
        TsharkRunner(FIXTURES / "rsa_kx.pcap", use_cache=False), decrypt_args=tuple(km.tshark_args())
    ).build()
    assert len(plain.http) == 0  # the capture is all TLS: no cleartext HTTP without the key
    assert len(keyed.http) > 0  # decrypted HTTP is now visible to the HTTP pass (and to the d2 detectors)
    assert any("read inner traffic from" in n and "TLS session" in n for n in keyed.notes)


@requires_tshark
def test_cli_decrypts_and_notes_it(cli_runner, tmp_path, cache_dir) -> None:
    args = ["analyze", str(FIXTURES / "rsa_kx.pcap"), "-o", str(tmp_path / "r"), "-q", "--no-handoff",
            "--tls-key", str(FIXTURES / KEY)]
    assert cli_runner.invoke(app, args).exit_code == 0
    assert any("[decrypt] read inner traffic from" in n for n in _notes(tmp_path / "r"))


@requires_tshark
def test_keys_from_a_directory(cli_runner, tmp_path, cache_dir) -> None:
    # FIXTURES holds rsa_kx.key; --keys-from loads it by walking the tree.
    args = ["analyze", str(FIXTURES / "rsa_kx.pcap"), "-o", str(tmp_path / "r"), "-q", "--no-handoff",
            "--keys-from", str(FIXTURES)]
    assert cli_runner.invoke(app, args).exit_code == 0
    assert any("[decrypt]" in n for n in _notes(tmp_path / "r"))


def test_a_nonexistent_key_exits_2(cli_runner, tmp_path) -> None:
    result = cli_runner.invoke(app, ["analyze", str(FIXTURES / "rsa_kx.pcap"), "-o", str(tmp_path / "r"),
                                     "--tls-key", str(tmp_path / "missing.key")])
    assert result.exit_code == 2


@requires_tshark
def test_no_key_material_reaches_any_artifact(cli_runner, tmp_path, cache_dir) -> None:
    key = FIXTURES / KEY
    args = ["analyze", str(FIXTURES / "rsa_kx.pcap"), "-o", str(tmp_path / "r"), "-q", "--no-handoff",
            "--tls-key", str(key), "--json-out", str(tmp_path / "env.json"), "--sarif", str(tmp_path / "out.sarif")]
    assert cli_runner.invoke(app, args).exit_code == 0
    key_bytes = key.read_text()[:60]
    blob = "".join(p.read_text(errors="ignore") for p in (tmp_path / "r").glob("*")) \
        + (tmp_path / "env.json").read_text() + (tmp_path / "out.sarif").read_text()
    assert str(key) not in blob  # the key path never appears
    assert "uat:ssl_keys" not in blob and "PRIVATE KEY" not in blob and key_bytes not in blob
