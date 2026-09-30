"""Operator key material becomes tshark decryption args; nothing here is ever written to a report (#115)."""

from __future__ import annotations

from pathlib import Path

from pcapforensics.keymaterial import KeyMaterial, collect, private_keys_under


def test_empty_material() -> None:
    assert KeyMaterial().is_empty()
    assert KeyMaterial().tshark_args() == []
    assert not KeyMaterial(psk="00").is_empty()


def test_rsa_key_uses_the_modern_uat_form_not_the_obsolete_pref() -> None:
    args = KeyMaterial(tls_keys=(Path("/k/a.key"), Path("/k/b.key"))).tshark_args()
    assert args == [
        "-o", 'uat:ssl_keys:"","","http","/k/a.key",""',
        "-o", 'uat:ssl_keys:"","","http","/k/b.key",""',
    ]
    joined = " ".join(args)
    assert "tls.keys_list" not in joined  # obsolete on tshark 4.x, hard-fails
    assert 'uat:ssl_keys:"","","http"' in joined  # wildcard ip/port matches any server


def test_password_keylog_and_psk_args() -> None:
    km = KeyMaterial(tls_keys=(Path("/k/a.key"),), tls_key_password="pw", keylog=Path("/k/log"), psk="ABCD")
    assert km.tshark_args() == [
        "-o", 'uat:ssl_keys:"","","http","/k/a.key","pw"',
        "-o", "tls.keylog_file:/k/log",
        "-o", "tls.psk:ABCD",
        "-o", "dtls.psk:ABCD",
    ]


def test_collect_expands_keys_from_a_firmware_tree(tmp_path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "server.key").write_text("-----BEGIN RSA PRIVATE KEY-----\nx\n")
    (tmp_path / "ca.pem").write_text("-----BEGIN CERTIFICATE-----\ny\n")  # a cert, not a private key
    (tmp_path / "leaf.pem").write_text("-----BEGIN PRIVATE KEY-----\nz\n")
    (tmp_path / "notes.txt").write_text("-----BEGIN RSA PRIVATE KEY-----\n")  # wrong extension, ignored
    found = [p.name for p in private_keys_under(tmp_path)]
    assert found == ["leaf.pem", "server.key"]  # only PEM private keys, sorted
    km = collect([tmp_path / "explicit.key"], keys_from=tmp_path)
    assert Path(tmp_path / "explicit.key") in km.tls_keys and len(km.tls_keys) == 3
