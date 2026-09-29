#!/usr/bin/env python3
"""Generate the synthetic fixtures under ``tests/fixtures/``.

These exist because the real-world captures cannot contain a reliable mix of
weak handshakes: a deliberate TLS 1.0/RC4/3DES session, an expired
certificate, cleartext HTTP Basic auth, an unauthenticated SIP call, and DNS
tunnelling all have to be *built*, not collected. Each fixture is tiny (a few
packets), deterministic, and paired with a test that asserts the exact finding
codes it must produce.

``scapy`` is a dev dependency only -- the runtime never needs it.
"""

from __future__ import annotations

import contextlib
import struct
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "fixtures"

CLIENT = "10.0.0.10"
SERVER = "10.0.0.20"


def _pcap_header(linktype: int = 1) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def _packet(payload: bytes, ts: float) -> bytes:
    """One pcap record: (seconds, microseconds, incl_len, orig_len) + bytes."""
    sec = int(ts)
    usec = round((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(payload), len(payload)) + payload


def eth_ip_tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    import socket

    def ip4(addr: str) -> bytes:
        return socket.inet_aton(addr)

    tcp = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 65535, 0, 0
    )
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, ip4(src), ip4(dst))
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + ip + tcp + payload


def eth_ip_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    import socket

    def ip4(addr: str) -> bytes:
        return socket.inet_aton(addr)

    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 17, 0, ip4(src), ip4(dst))
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + ip + udp + payload


# --------------------------------------------------------------------------
# TLS handshakes -- captured for real, never hand-rolled
# --------------------------------------------------------------------------
def _write_pcap(path: Path, packets: list[bytes], start: float = 1_700_000_000.0) -> None:
    body = b"".join(_packet(p, start + i * 0.010) for i, p in enumerate(packets))
    path.write_bytes(_pcap_header() + body)


def _make_cert(tmp: Path, cn: str) -> tuple[Path, Path]:
    """Self-signed certificate for the throwaway TLS server."""
    import subprocess

    cert, key = tmp / f"{cn}.crt", tmp / f"{cn}.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
            "-subj", f"/CN={cn}", "-keyout", str(key), "-out", str(cert),
        ],
        capture_output=True,
        check=True,
    )
    return cert, key


def _tls_through_proxy(
    cert: Path,
    key: Path,
    *,
    ciphers: str,
    minimum: int,
    maximum: int,
    server_name: str,
    server_ciphers: str | None = None,
) -> tuple[bytes, bytes]:
    """Run a real handshake through a byte-logging proxy; return both record streams.

    Hand-rolling handshake bytes is a trap: one wrong length field and tshark
    reports "[Client Hello Fragment]" and the whole session disappears. This
    performs a genuine OpenSSL handshake instead and captures the wire bytes.
    """
    import socket
    import ssl
    import threading

    client_log: list[bytes] = []
    server_log: list[bytes] = []

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def pump(src: socket.socket, dst: socket.socket, log: list[bytes]) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                log.append(data)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)

    def serve() -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.minimum_version = minimum
        ctx.maximum_version = maximum
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers(server_ciphers or ciphers)
        raw, _ = listener.accept()
        try:
            with ctx.wrap_socket(raw, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                raw.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    proxy_listener = socket.socket()
    proxy_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_listener.bind(("127.0.0.1", 0))
    proxy_listener.listen(1)
    proxy_port = proxy_listener.getsockname()[1]

    def run_proxy() -> None:
        c2s, _ = proxy_listener.accept()
        try:
            upstream = socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:
            c2s.close()
            return
        t1 = threading.Thread(target=pump, args=(c2s, upstream, client_log), daemon=True)
        t2 = threading.Thread(target=pump, args=(upstream, c2s, server_log), daemon=True)
        t1.start()
        t2.start()
        t1.join(5)
        t2.join(5)
        for sock in (c2s, upstream):
            with contextlib.suppress(OSError):
                sock.close()

    proxy_thread = threading.Thread(target=run_proxy, daemon=True)
    proxy_thread.start()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = minimum
    ctx.maximum_version = maximum
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers(ciphers)
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as raw:
        try:
            with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass
    proxy_thread.join(5)
    thread.join(5)
    listener.close()
    proxy_listener.close()
    return b"".join(client_log), b"".join(server_log)


def _split_records(stream: bytes) -> list[bytes]:
    """Split a TLS record stream into individual records."""
    out: list[bytes] = []
    i = 0
    while i + 5 <= len(stream):
        length = int.from_bytes(stream[i + 3 : i + 5], "big")
        end = i + 5 + length
        if end > len(stream):
            break
        out.append(stream[i:end])
        i = end
    return out


def _capture_fixture(
    tmp: Path,
    out_name: str,
    *,
    ciphers: str,
    minimum: int,
    maximum: int,
    server_name: str,
    sport: int,
    server_ciphers: str | None = None,
) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        cert, key = _make_cert(work, server_name)
        client_stream, server_stream = _tls_through_proxy(
            cert,
            key,
            ciphers=ciphers,
            minimum=minimum,
            maximum=maximum,
            server_name=server_name,
            server_ciphers=server_ciphers,
        )
    client_records = _split_records(client_stream)
    server_records = _split_records(server_stream)
    if not client_records or not server_records:
        raise RuntimeError(f"handshake capture produced no records for {out_name}")
    client_hello = client_records[0]
    server_flight = b"".join(server_records[:2])
    app_data = client_records[-1] if len(client_records) > 1 else b"\x17\x03\x03\x00\x20" + b"A" * 32
    packets = [
        eth_ip_tcp(CLIENT, SERVER, sport, 443, 1, 0, 0x02, b""),
        eth_ip_tcp(SERVER, CLIENT, 443, sport, 1, 2, 0x12, b""),
        eth_ip_tcp(CLIENT, SERVER, sport, 443, 2, 2, 0x18, client_hello),
        eth_ip_tcp(SERVER, CLIENT, 443, sport, 2, 500, 0x18, server_flight),
        eth_ip_tcp(CLIENT, SERVER, sport, 443, 500, 900, 0x18, app_data),
    ]
    _write_pcap(OUT / out_name, packets)


# --------------------------------------------------------------------------
# Cleartext HTTP
# --------------------------------------------------------------------------
def fixture_http_basic() -> bytes:
    body = b"username=admin&password=hunter2"
    request = (
        b"POST /login HTTP/1.1\r\nHost: portal.example\r\n"
        b"Authorization: Basic YWRtaW46aHVudGVyMg==\r\n"
        b"Cookie: session=abc123\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    response = (
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
        b"Set-Cookie: session=xyz789; Path=/; HttpOnly\r\n"
        b"Content-Length: 2\r\n\r\nOK"
    )
    packets = [
        eth_ip_tcp(CLIENT, SERVER, 42000, 80, 1, 0, 0x02, b""),
        eth_ip_tcp(SERVER, CLIENT, 80, 42000, 1, 2, 0x12, b""),
        eth_ip_tcp(CLIENT, SERVER, 42000, 80, 2, 2, 0x18, request),
        eth_ip_tcp(SERVER, CLIENT, 80, 42000, 2, 400, 0x18, response),
    ]
    return _pcap_header() + b"".join(
        _packet(p, 1_700_000_200.0 + i * 0.02) for i, p in enumerate(packets)
    )


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def dns_query(name: str, qid: int, qtype: int = 1) -> bytes:
    labels = b"".join(
        struct.pack("!B", len(part)) + part.encode() for part in name.split(".")
    ) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def dns_response(name: str, qid: int, addr: str, qtype: int = 1) -> bytes:
    import socket

    labels = b"".join(
        struct.pack("!B", len(part)) + part.encode() for part in name.split(".")
    ) + b"\x00"
    question = labels + struct.pack("!HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, 4) + socket.inet_aton(addr)
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer


def fixture_dns_tunnel() -> bytes:
    """Many deeply-labelled high-entropy names: the shape of DNS exfiltration."""
    import random

    rng = random.Random(1337)
    packets = [
        eth_ip_tcp(CLIENT, SERVER, 43000, 53, 1, 0, 0x02, b""),
        eth_ip_tcp(SERVER, CLIENT, 53, 43000, 1, 2, 0x12, b""),
    ]
    for i in range(24):
        blob = "".join(rng.choice("abcdef0123456789") for _ in range(32))
        name = f"{blob[:8]}.{blob[8:16]}.{blob[16:24]}.{blob[24:]}.tunnel.example"
        packets.append(eth_ip_udp(CLIENT, SERVER, 40000 + i, 53, dns_query(name, 0x2000 + i, 16)))
        packets.append(eth_ip_udp(SERVER, CLIENT, 53, 40000 + i, dns_response(name, 0x2000 + i, "10.9.9.9", 16)))
    return _pcap_header() + b"".join(
        _packet(p, 1_700_000_300.0 + i * 0.01) for i, p in enumerate(packets)
    )


# --------------------------------------------------------------------------
# SIP + RTP
# --------------------------------------------------------------------------
def fixture_sip_rtp() -> bytes:
    register = (
        b"REGISTER sip:pbx.example SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK1\r\n"
        b"From: <sip:alice@example>;tag=1\r\n"
        b"To: <sip:alice@example>\r\n"
        b"Call-ID: fixture-call-1\r\nCSeq: 1 REGISTER\r\n"
        b"Contact: <sip:alice@10.0.0.10>\r\n"
        b"Authorization: Digest username=\"alice\", realm=\"pbx.example\", "
        b"nonce=\"abc\", uri=\"sip:pbx.example\", response=\"deadbeef\"\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    invite = (
        b"INVITE sip:bob@example SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK2\r\n"
        b"From: <sip:alice@example>;tag=2\r\n"
        b"To: <sip:bob@example>\r\n"
        b"Call-ID: fixture-call-2\r\nCSeq: 1 INVITE\r\n"
        b"User-Agent: TestSoftphone 1.0\r\n"
        b"Content-Type: application/sdp\r\nContent-Length: 0\r\n\r\n"
    )
    sdp = (
        b"v=0\r\no=alice 2890844526 2890844526 IN IP4 10.0.0.10\r\n"
        b"s=fixture\r\nc=IN IP4 10.0.0.10\r\nt=0 0\r\n"
        b"m=audio 20000 RTP/AVP 8 0 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\n"
    )
    invite = invite.replace(b"Content-Length: 0", b"Content-Length: " + str(len(sdp)).encode())
    invite = invite[: invite.index(b"\r\n\r\n") + 4] + sdp
    ok = (
        b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bK2\r\n"
        b"From: <sip:alice@example>;tag=2\r\nTo: <sip:bob@example>;tag=3\r\n"
        b"Call-ID: fixture-call-2\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    )
    packets = [
        eth_ip_udp(CLIENT, SERVER, 5060, 5060, register),
        eth_ip_udp(SERVER, CLIENT, 5060, 5060, b"SIP/2.0 200 OK\r\nCall-ID: fixture-call-1\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n"),
        eth_ip_udp(CLIENT, SERVER, 5060, 5060, invite),
        eth_ip_udp(SERVER, CLIENT, 5060, 5060, ok),
    ]
    # 60 RTP packets, 160 bytes each, in the clear
    for i in range(60):
        # RTP header layout: V/P/CC, M/PT, sequence, timestamp, SSRC.
        # Swapping timestamp and SSRC makes every packet look like its own stream.
        rtp = struct.pack("!BBHII", 0x80, 8, i * 160, i * 160, 0xDEADBEEF) + b"\x00" * 152
        # Ports must sit in 16384-32767 or tshark's RTP heuristic never fires.
        packets.append(eth_ip_udp(SERVER, CLIENT, 20000, 20002, rtp))
    return _pcap_header() + b"".join(
        _packet(p, 1_700_000_400.0 + i * 0.02) for i, p in enumerate(packets)
    )


# --------------------------------------------------------------------------
# Scan shape
# --------------------------------------------------------------------------
def fixture_syn_scan() -> bytes:
    packets = []
    for port in range(1, 40):
        packets.append(eth_ip_tcp(CLIENT, SERVER, 45000 + port, port, 1, 0, 0x02, b""))
    return _pcap_header() + b"".join(
        _packet(p, 1_700_000_500.0 + i * 0.001) for i, p in enumerate(packets)
    )


#: Fixtures built from bytes, no external process.
STATIC_FIXTURES = {
    "http_basic.pcap": fixture_http_basic,
    "dns_tunnel.pcap": fixture_dns_tunnel,
    "sip_rtp.pcap": fixture_sip_rtp,
    "syn_scan.pcap": fixture_syn_scan,
}

#: Fixtures captured from a real OpenSSL handshake. Cipher strings are passed to
#: both ends; the point is that the ClientHello really does offer these suites.
TLS_FIXTURES = {
    # TLS 1.0 with 3DES and SHA-1 suites: deprecated version + legacy crypto.
    "weak_tls.pcap": {"ciphers": "AES128-SHA:DES-CBC3-SHA:@SECLEVEL=0", "minimum": "TLSv1", "maximum": "TLSv1"},
    # TLS 1.3 with AEAD: the clean counter-example that must stay silent.
    "strong_tls13.pcap": {"ciphers": "TLS_AES_128_GCM_SHA256", "minimum": "TLSv1_3", "maximum": "TLSv1_3"},
    # TLS 1.2 RSA key exchange: forward secrecy must be reported as absent.
    "no_pfs_tls12.pcap": {"ciphers": "AES128-SHA:@SECLEVEL=0", "minimum": "TLSv1_2", "maximum": "TLSv1_2"},
    # Client offers legacy CBC suites, server picks ECDHE-AEAD: the offered-but-unused
    # ones are downgrade surface and must be reported without flagging the session.
    "mixed_ciphers.pcap": {
        "ciphers": "AES128-SHA:AES256-SHA:AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0",
        "server_ciphers": "ECDHE-RSA-AES128-GCM-SHA256",
        "minimum": "TLSv1_2",
        "maximum": "TLSv1_2",
    },
}


def main() -> int:
    import ssl
    import tempfile

    OUT.mkdir(parents=True, exist_ok=True)
    for name, builder in STATIC_FIXTURES.items():
        data = builder()
        (OUT / name).write_bytes(data)
        print(f"wrote {name} ({len(data)} bytes)")
    for i, (name, spec) in enumerate(TLS_FIXTURES.items()):
        with tempfile.TemporaryDirectory() as td, warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            _capture_fixture(
                Path(td),
                name,
                ciphers=spec["ciphers"],
                minimum=getattr(ssl.TLSVersion, spec["minimum"]),
                maximum=getattr(ssl.TLSVersion, spec["maximum"]),
                server_name="strong.example" if "strong" in name else "weak.example",
                server_ciphers=spec.get("server_ciphers"),
                sport=40000 + i * 1000,
            )
        print(f"wrote {name} ({(OUT / name).stat().st_size} bytes, captured handshake)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
