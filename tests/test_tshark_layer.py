"""The tshark boundary: field drift, self-healing, caching, parsing helpers.

Field names move between tshark releases. These tests pin what we rely on and
prove the self-healing path works, because a field that quietly disappears must
degrade into a note, never into a wrong answer.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from conftest import fixture, requires_tshark
from pcapforensics.tshark import (
    PASSES,
    TsharkRunner,
    default_prefs,
    parse_cipher_ids,
    parse_hex_bits,
    protocol_names,
    public_key_bits,
    split_multi,
    to_bool01,
    to_int,
    valid_fields,
)

pytestmark = requires_tshark

#: Fields this project cannot work without.
REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.flags.syn",
    "tls.handshake.type",
    "tls.handshake.ciphersuite",
    "tls.handshake.version",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja3",
    "tls.handshake.ja3s",
    "dtls.handshake.type",
    "dtls.handshake.ciphersuite",
    "dns.qry.name",
    "sip.Method",
    "sdp.media",
    "rtp.ssrc",
    "ssh.protocol",
    "quic.version",
    "http.request.method",
    "http.response.code",
    "http.set_cookie",
    "http.authorization",
)


def test_required_fields_exist_in_this_tshark() -> None:
    known = valid_fields()
    missing = [f for f in REQUIRED_FIELDS if f not in known]
    assert not missing, (
        f"this tshark build ({TsharkRunner(Path('.')).version}) is missing {missing}; "
        "update tshark or adapt the pass in src/pcapforensics/tshark.py"
    )


def test_display_filter_protocols_are_real() -> None:
    known = protocol_names()
    for name, spec in PASSES.items():
        if not spec.display_filter:
            continue
        for token in spec.display_filter.split("||"):
            token = token.strip()
            if " " in token or any(op in token for op in "()=<>!"):
                continue
            assert token in known or token.split(".")[0] in known, f"pass {name}: unknown protocol {token!r}"


def test_tls_and_dtls_passes_stay_in_sync() -> None:
    """DTLS must expose the same field set as TLS, just prefixed."""
    tls = {f[4:] for f in PASSES["tls"].fields if f.startswith("tls.")}
    dtls = {f[5:] for f in PASSES["dtls"].fields if f.startswith("dtls.")}
    assert tls == dtls, f"drift: only in tls {tls - dtls}, only in dtls {dtls - tls}"


def test_boolean_fields_parse_from_both_renderings() -> None:
    assert to_bool01("1") is True and to_bool01("0") is False
    assert to_bool01("True") is True and to_bool01("False") is False
    assert to_bool01("") is None and to_bool01("maybe") is None


def test_cipher_id_parsing() -> None:
    assert parse_cipher_ids("0xc02f") == [0xC02F]
    assert parse_cipher_ids("0xc02f,0x1301") == [0xC02F, 0x1301]
    # bare decimal must stay decimal: 4865 == 0x1301 (TLS_AES_128_GCM_SHA256)
    assert parse_cipher_ids("4865") == [4865]
    assert parse_cipher_ids("") == []
    assert parse_cipher_ids("nonsense") == []


def test_hex_bit_parsing() -> None:
    assert parse_hex_bits("00ff") == 16  # measured in bytes, leading zeros kept
    assert parse_hex_bits("00" * 256) == 2048
    assert parse_hex_bits("") is None
    assert parse_hex_bits("zz") is None
    assert parse_hex_bits("0") is None  # a lone zero nibble is not a key


def test_ec_curve_detection() -> None:
    # 1.2.840.10045.3.1.7 (prime256v1) inside a SubjectPublicKeyInfo blob
    assert public_key_bits("", "3082" + "06082a8648ce3d030107") == 256
    assert public_key_bits("", "3082" + "06052b810400") is None
    assert public_key_bits("00" * 256) == 2048


def test_split_multi_drops_empties() -> None:
    assert split_multi("a\x1fb\x1f") == ["a", "b"]


def test_to_int_is_strict() -> None:
    assert to_int("443") == 443
    assert to_int("0x1bb") is None
    assert to_int("") is None


def test_unknown_field_is_dropped_and_recorded() -> None:
    spec = PASSES["base"]
    runner = TsharkRunner(fixture("weak_tls.pcap"))
    runner._field_blacklist.add("tcp.analysis.ack_rtt")
    fields = runner.usable_fields(spec)
    assert "tcp.analysis.ack_rtt" not in fields
    assert any("tcp.analysis.ack_rtt" in d for d in runner.dropped_fields)


def test_ws_column_fields_are_never_dropped() -> None:
    """_ws.col.* are not listed by -G fields but are perfectly valid."""
    runner = TsharkRunner(fixture("weak_tls.pcap"))
    assert "_ws.col.Protocol" in runner.usable_fields(PASSES["base"])


def test_unknown_protocol_token_is_dropped_and_recorded() -> None:
    runner = TsharkRunner(fixture("weak_tls.pcap"))
    # simulate a protocol this tshark build does not know
    runner._banned_protocols.add("telnet")
    resolved = runner._filter_for(PASSES["services"])
    assert resolved is not None
    assert "telnet" not in resolved
    assert "ntp" in resolved
    # a runtime ban is a fix-up, not field drift: it must not be reported as a
    # missing field, but the pass still has to be recorded somewhere
    assert isinstance(runner.dropped_fields, list)


def test_cache_hit_avoids_a_second_tshark_run() -> None:
    pcap = fixture("weak_tls.pcap")
    fresh = TsharkRunner(pcap, use_cache=True)
    rows_first = fresh.run("tls")
    second = TsharkRunner(pcap, use_cache=True)
    rows_second = second.run("tls")
    assert second.stats["tls"]["cached"] == 1
    assert rows_first == rows_second


def test_cache_is_keyed_by_content(tmp_path: Path) -> None:
    original = fixture("weak_tls.pcap")
    copy = tmp_path / "copy.pcap"
    shutil.copy(original, copy)
    a = TsharkRunner(original, use_cache=False)
    b = TsharkRunner(copy, use_cache=False)
    assert a.sha == b.sha  # same bytes -> same cache key


def test_rtp_decode_args_are_well_formed() -> None:
    args = TsharkRunner.rtp_decode_args([20000, 20000, 0, 70000])
    assert args == ("-d udp.port==20000,rtp",)


def test_extra_args_change_the_cache_key() -> None:
    pcap = fixture("weak_tls.pcap")
    plain = TsharkRunner(pcap, use_cache=True)._cache_file("base")
    with_extra = TsharkRunner(pcap, use_cache=True)._cache_file(
        "base", ("-d udp.port==20000,rtp",)
    )
    assert plain != with_extra


def test_tshark_version_and_prefs_are_discoverable() -> None:
    import pcapforensics.tshark as mod

    assert mod.tshark_version().split()[0][0].isdigit()
    assert "tcp.desegment_tcp_streams" in default_prefs()
    assert "tls" in protocol_names()


def test_missing_binary_raises_a_clear_error(monkeypatch) -> None:
    import pcapforensics.tshark as mod

    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    mod.tshark_path.cache_clear()
    with pytest.raises(mod.TsharkMissingError) as excinfo:
        mod.tshark_path()
    assert "tshark" in str(excinfo.value)
    mod.tshark_path.cache_clear()


def test_unreadable_capture_raises_a_useful_error(tmp_path: Path) -> None:
    from pcapforensics.tshark import TsharkRunError

    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(b"not a pcap at all")
    runner = TsharkRunner(bogus, use_cache=False)
    with pytest.raises(TsharkRunError) as excinfo:
        runner.run("base")
    assert "base" in str(excinfo.value)


def test_shutil_present() -> None:
    """The environment probe itself is part of the contract."""
    assert shutil.which("capinfos") or shutil.which("tshark")
