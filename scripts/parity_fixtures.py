"""Byte-built fixtures and packet helpers for the parity features (issues #199 onward).

Everything here is deterministic and carries valid IP/TCP/UDP checksums (so checksum validation, #209, stays
quiet on them) unless a builder asks for a bad one. ``make_fixtures.py`` merges ``FIXTURES`` into its table.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from pathlib import Path

FIXTURES: dict[str, Callable[[], bytes]] = {}


def fixture(name: str) -> Callable[[Callable[[], bytes]], Callable[[], bytes]]:
    def register(fn: Callable[[], bytes]) -> Callable[[], bytes]:
        FIXTURES[name] = fn
        return fn

    return register


def mac(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(":"))


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def ip_packet(
    src: str, dst: str, proto: int, l4: bytes, *, ttl: int = 64, ident: int = 0, flags_frag: int = 0x4000,
    bad_ip_checksum: bool = False,
) -> bytes:
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ident, flags_frag, ttl, proto, 0, _ip4(src), _ip4(dst))
    c = csum(head) ^ (0x1234 if bad_ip_checksum else 0)
    return head[:10] + struct.pack("!H", c) + head[12:] + l4


def ether(src_mac: str, dst_mac: str, payload: bytes, ethertype: int = 0x0800) -> bytes:
    return mac(dst_mac) + mac(src_mac) + struct.pack("!H", ethertype) + payload


def tcp_segment(
    src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", *,
    window: int = 65535, options: bytes = b"", bad_checksum: bool = False,
) -> bytes:
    off = (20 + len(options)) // 4
    head = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, window, 0, 0) + options
    pseudo = _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, 6, len(head) + len(payload))
    c = csum(pseudo + head + payload) ^ (0x4321 if bad_checksum else 0)
    return head[:16] + struct.pack("!H", c) + head[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes, *, bad_checksum: bool = False) -> bytes:
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, 17, length)
    c = (csum(pseudo + head + payload) or 0xFFFF) ^ (0x4321 if bad_checksum else 0)
    return head[:6] + struct.pack("!H", c) + payload


MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


class Wire:
    """Collects frames with a clock; ``write()`` returns the pcap bytes."""

    def __init__(self, start: float = 1_700_100_000.0, step: float = 0.01) -> None:
        self.t, self.step = start, step
        self.frames: list[tuple[float, bytes]] = []

    def add(self, frame: bytes, dt: float | None = None) -> None:
        self.t += self.step if dt is None else dt
        self.frames.append((self.t, frame))

    def write(self) -> bytes:
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for ts, frame in self.frames:
            sec = int(ts)
            out += struct.pack("<IIII", sec, round((ts - sec) * 1_000_000), len(frame), len(frame)) + frame
        return out


class Tcp:
    """One TCP connection with consistent sequence numbers; every method also emits into ``wire``."""

    def __init__(self, wire: Wire, client: str, server: str, sport: int, dport: int, *,
                 cmac: str = MAC_A, smac: str = MAC_B, isn_c: int = 1000, isn_s: int = 5000) -> None:
        self.w, self.c, self.s, self.sp, self.dp = wire, client, server, sport, dport
        self.cmac, self.smac = cmac, smac
        self.seq_c, self.seq_s = isn_c, isn_s

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"", **kw: object) -> None:
        if from_client:
            ack = 0 if flags == 0x02 else self.seq_s
            seg = tcp_segment(self.c, self.s, self.sp, self.dp, self.seq_c, ack, flags, payload, **kw)  # type: ignore[arg-type]
            frame = ether(self.cmac, self.smac, ip_packet(self.c, self.s, 6, seg))
        else:
            seg = tcp_segment(self.s, self.c, self.dp, self.sp, self.seq_s, self.seq_c, flags, payload, **kw)  # type: ignore[arg-type]
            frame = ether(self.smac, self.cmac, ip_packet(self.s, self.c, 6, seg))
        self.w.add(frame)

    def open(self) -> Tcp:
        self._emit(True, 0x02)
        self.seq_c += 1
        self._emit(False, 0x12)
        self.seq_s += 1
        self._emit(True, 0x10)
        return self

    def send(self, from_client: bool, payload: bytes, ack: bool = True) -> Tcp:
        self._emit(from_client, 0x18, payload)
        if from_client:
            self.seq_c += len(payload)
        else:
            self.seq_s += len(payload)
        if ack:
            self._emit(not from_client, 0x10)
        return self

    def close(self) -> Tcp:
        self._emit(True, 0x11)
        self.seq_c += 1
        self._emit(False, 0x11)
        self.seq_s += 1
        self._emit(True, 0x10)
        return self


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, *, smac: str = MAC_A, dmac: str = MAC_B,
              **kw: object) -> bytes:
    return ether(smac, dmac, ip_packet(src, dst, 17, udp_datagram(src, dst, sport, dport, payload, **kw)))  # type: ignore[arg-type]


# -- NTLM / SMB2 builders (also used by the Kerberos and NTLM fixtures) -------------------------------
def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _secbuf(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def ntlm_negotiate() -> bytes:
    return b"NTLMSSP\x00" + struct.pack("<II", 1, 0xE2088297) + _secbuf(0, 32) + _secbuf(0, 32)


def ntlm_challenge(challenge: bytes, target: str = "CORP") -> bytes:
    tname = utf16(target)
    info = struct.pack("<HH", 2, len(tname)) + tname + struct.pack("<HH", 0, 0)  # MsvAvNbDomainName, MsvAvEOL
    head = b"NTLMSSP\x00" + struct.pack("<I", 2) + _secbuf(len(tname), 56) + struct.pack("<I", 0xE2898215)
    head += challenge + bytes(8) + _secbuf(len(info), 56 + len(tname)) + bytes(8)
    return head + tname + info


def ntlm_authenticate(user: str, domain: str, workstation: str, nt_response: bytes, lm_response: bytes = b"\x00" * 24) -> bytes:
    parts = [lm_response, nt_response, utf16(domain), utf16(user), utf16(workstation), b""]
    offset = 64 + 8
    fields = b""
    for p in parts:
        fields += _secbuf(len(p), offset)
        offset += len(p)
    head = b"NTLMSSP\x00" + struct.pack("<I", 3) + fields + struct.pack("<I", 0xE2888215) + bytes(8)
    return head + b"".join(parts)


def smb2_message(command: int, body: bytes, *, response: bool = False, msg_id: int = 0, tree: int = 0,
                 session: int = 0, status: int = 0, credits: int = 1) -> bytes:
    flags = 1 if response else 0
    head = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, status, command, credits, flags, 0, msg_id, 0, tree, session)
            + bytes(16))
    pdu = head + body
    return b"\x00" + struct.pack(">I", len(pdu))[1:] + pdu  # NetBIOS session header


def smb2_negotiate_request(dialects: tuple[int, ...] = (0x0202, 0x0210, 0x0300)) -> bytes:
    body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0x7F, bytes(range(16)), 0)
    body += b"".join(struct.pack("<H", d) for d in dialects)
    return smb2_message(0, body)


def smb2_negotiate_response(dialect: int = 0x0210) -> bytes:
    body = struct.pack("<HHHH16sIIIIQQHHI", 65, 1, dialect, 0, bytes(16)[::-1] or bytes(16), 0x7, 65536, 65536, 65536,
                       132_000_000_000_000_000, 132_000_000_000_000_000, 128, 0, 0) + b"\x00"
    return smb2_message(0, body, response=True, credits=1)


def smb2_session_setup(blob: bytes, *, response: bool = False, msg_id: int = 1, session: int = 0,
                       status: int = 0) -> bytes:
    if response:
        body = struct.pack("<HHHH", 9, 0, 72, len(blob)) + blob
    else:
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(blob), 0) + blob
    return smb2_message(1, body, response=response, msg_id=msg_id, session=session, status=status)


def smb2_tree_connect(path: str, *, tree: int = 0, msg_id: int = 3, session: int = 0x100) -> bytes:
    raw = utf16(path)
    return smb2_message(3, struct.pack("<HHHH", 9, 0, 72, len(raw)) + raw, msg_id=msg_id, session=session)


def smb2_tree_connect_response(*, tree: int = 1, msg_id: int = 3, session: int = 0x100) -> bytes:
    return smb2_message(3, struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x1F01FF), response=True, msg_id=msg_id,
                        tree=tree, session=session)


def smb2_create(name: str, *, tree: int = 1, msg_id: int = 4, session: int = 0x100) -> bytes:
    raw = utf16(name)
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x120089, 0x80, 7, 1, 0x40, 120, len(raw), 0, 0) + raw
    return smb2_message(5, body, msg_id=msg_id, tree=tree, session=session)


def smb2_create_response(*, tree: int = 1, msg_id: int = 4, session: int = 0x100, size: int = 0,
                         fid: bytes = b"\x01" * 16) -> bytes:
    body = struct.pack("<HBBIQQQQQQII", 89, 0, 0, 1, 0, 0, 0, 0, size, size, 0x80, 0) + fid + struct.pack("<II", 0, 0)
    return smb2_message(5, body, response=True, msg_id=msg_id, tree=tree, session=session)


def dns_wire(name: str, qid: int, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def dhcp_message(op: int, xid: int, client_mac: str, msg_type: int, *, ciaddr: str = "0.0.0.0", yiaddr: str = "0.0.0.0",
                 options: bytes = b"") -> bytes:
    head = struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000, _ip4(ciaddr), _ip4(yiaddr), bytes(4), bytes(4))
    head += mac(client_mac) + bytes(10) + bytes(64) + bytes(128) + b"\x63\x82\x53\x63"
    return head + bytes([53, 1, msg_type]) + options + b"\xff"


@fixture("logs_mix.pcap")
def fixture_logs_mix() -> bytes:
    """DHCP, an SMTP mail, an SMB2 session (NTLM) and a malformed DNS packet: the protocols the Zeek-style logs add (#199)."""
    w = Wire()
    cl_mac = "02:aa:bb:cc:dd:01"
    # DHCP
    w.add(udp_frame("0.0.0.0", "255.255.255.255", 68, 67, dhcp_message(1, 0x1234, cl_mac, 1, options=bytes([12, 9]) + b"pf-laptop"),
                    smac=cl_mac, dmac="ff:ff:ff:ff:ff:ff"))
    srv = "10.0.0.1"
    offer = dhcp_message(2, 0x1234, cl_mac, 2, yiaddr="10.0.0.50", options=bytes([54, 4]) + _ip4(srv) + bytes([51, 4]) + struct.pack("!I", 3600))
    w.add(udp_frame(srv, "255.255.255.255", 67, 68, offer, smac=MAC_B, dmac="ff:ff:ff:ff:ff:ff"))
    w.add(udp_frame("0.0.0.0", "255.255.255.255", 68, 67,
                    dhcp_message(1, 0x1234, cl_mac, 3, options=bytes([12, 9]) + b"pf-laptop" + bytes([50, 4]) + _ip4("10.0.0.50")),
                    smac=cl_mac, dmac="ff:ff:ff:ff:ff:ff"))
    w.add(udp_frame(srv, "255.255.255.255", 67, 68, dhcp_message(2, 0x1234, cl_mac, 5, yiaddr="10.0.0.50", options=bytes([54, 4]) + _ip4(srv) + bytes([51, 4]) + struct.pack("!I", 3600)),
                    smac=MAC_B, dmac="ff:ff:ff:ff:ff:ff"))
    # SMTP
    c, s = "10.0.0.50", "10.0.0.25"
    t = Tcp(w, c, s, 44000, 25, cmac=cl_mac).open()
    t.send(False, b"220 mail.example ESMTP\r\n")
    t.send(True, b"EHLO pf-laptop\r\n")
    t.send(False, b"250 mail.example\r\n")
    t.send(True, b"MAIL FROM:<alice@example.com>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"RCPT TO:<bob@example.org>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"DATA\r\n")
    t.send(False, b"354 go ahead\r\n")
    t.send(True, b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: quarterly numbers\r\n"
                 b"Date: Tue, 14 Nov 2023 22:16:40 +0000\r\nMessage-ID: <pf-1@example.com>\r\n\r\nsee attached\r\n.\r\n")
    t.send(False, b"250 queued\r\n")
    t.send(True, b"QUIT\r\n")
    t.send(False, b"221 bye\r\n")
    t.close()
    # SMB2 with NTLM
    chal = bytes.fromhex("0123456789abcdef")
    t = Tcp(w, c, "10.0.0.30", 44100, 445, cmac=cl_mac).open()
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    t.send(True, smb2_session_setup(ntlm_negotiate(), msg_id=1))
    t.send(False, smb2_session_setup(ntlm_challenge(chal), response=True, msg_id=1, session=0x100, status=0xC0000016))
    t.send(True, smb2_session_setup(ntlm_authenticate("alice", "CORP", "PF-LAPTOP", bytes(range(16)) + b"\x01\x01" + bytes(30)), msg_id=2, session=0x100))
    t.send(False, smb2_session_setup(b"", response=True, msg_id=2, session=0x100))
    t.send(True, smb2_tree_connect("\\\\10.0.0.30\\ADMIN$"))
    t.send(False, smb2_tree_connect_response())
    t.send(True, smb2_create("windows\\temp\\payload.exe"))
    t.send(False, smb2_create_response())
    t.close()
    # malformed DNS: the question runs past the end of the packet
    w.add(udp_frame(c, "10.0.0.1", 40404, 53, dns_wire("bad.example", 7)[:-6]))
    return w.write()


def write_all(out: Path) -> None:  # pragma: no cover - used by make_fixtures
    for name, builder in FIXTURES.items():
        (out / name).write_bytes(builder())
