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


# -- files_mix.pcap: one file delivered over every protocol the extractor understands (#202, #203) ------------------
FILE_PAYLOADS = {
    "http": b"MZ\x90\x00" + b"PF-HTTP-PAYLOAD-" * 8,
    "ftp": b"%PDF-1.4\n" + b"PF-FTP-PAYLOAD-" * 8,
    "tftp": b"\x7fELF" + b"PF-TFTP-PAYLOAD-" * 4,
    "smb": b"PK\x03\x04" + b"PF-SMB-PAYLOAD-" * 8,
    "mail": b"\x89PNG\r\n\x1a\n" + b"PF-MAIL-PAYLOAD-" * 8,
}


def _mime_mail() -> bytes:
    import base64

    body = base64.encodebytes(FILE_PAYLOADS["mail"])
    return (b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: logo\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="PFBOUND"\r\n\r\n--PFBOUND\r\nContent-Type: text/plain\r\n\r\n'
            b"see logo\r\n--PFBOUND\r\nContent-Type: image/png; name=\"logo.png\"\r\n"
            b'Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="logo.png"\r\n\r\n'
            + body.replace(b"\n", b"\r\n") + b"--PFBOUND--\r\n")


@fixture("files_mix.pcap")
def fixture_files_mix() -> bytes:
    w = Wire(start=1_700_200_000.0)
    c = "10.1.0.5"
    # HTTP download
    t = Tcp(w, c, "10.1.0.80", 45000, 80).open()
    t.send(True, b"GET /dl/tool.exe HTTP/1.1\r\nHost: files.example\r\n\r\n")
    body = FILE_PAYLOADS["http"]
    t.send(False, b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    t.close()
    # FTP passive RETR: control on 21, data on 51210
    t = Tcp(w, c, "10.1.0.21", 45100, 21).open()
    t.send(False, b"220 ftp ready\r\n")
    t.send(True, b"USER anon\r\n")
    t.send(False, b"331 pw\r\n")
    t.send(True, b"PASS x\r\n")
    t.send(False, b"230 ok\r\n")
    t.send(True, b"PASV\r\n")
    t.send(False, b"227 Entering Passive Mode (10,1,0,21,200,10).\r\n")
    t.send(True, b"RETR report.pdf\r\n")
    d = Tcp(w, c, "10.1.0.21", 45101, 51210, isn_c=7000, isn_s=9000).open()
    t.send(False, b"150 Opening data connection\r\n")
    d.send(False, FILE_PAYLOADS["ftp"])
    d.close()
    t.send(False, b"226 done\r\n")
    t.close()
    # TFTP read
    srv = "10.1.0.69"
    w.add(udp_frame(c, srv, 50000, 69, b"\x00\x01fw.bin\x00octet\x00"))
    data = FILE_PAYLOADS["tftp"]
    w.add(udp_frame(srv, c, 40001, 50000, b"\x00\x03\x00\x01" + data))
    w.add(udp_frame(c, srv, 50000, 40001, b"\x00\x04\x00\x01"))
    # SMB2 write of a file
    t = Tcp(w, c, "10.1.0.30", 45200, 445).open()
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    t.send(True, smb2_session_setup(ntlm_negotiate(), msg_id=1))
    t.send(False, smb2_session_setup(ntlm_challenge(bytes(8)), response=True, msg_id=1, session=0x100, status=0xC0000016))
    t.send(True, smb2_session_setup(ntlm_authenticate("bob", "CORP", "PF", bytes(range(16)) + b"\x01\x01" + bytes(30)), msg_id=2, session=0x100))
    t.send(False, smb2_session_setup(b"", response=True, msg_id=2, session=0x100))
    t.send(True, smb2_tree_connect("\\\\10.1.0.30\\share"))
    t.send(False, smb2_tree_connect_response())
    t.send(True, smb2_create("docs\\archive.zip"))
    t.send(False, smb2_create_response())
    t.send(True, smb2_write(FILE_PAYLOADS["smb"]))
    t.send(False, smb2_write_response(len(FILE_PAYLOADS["smb"])))
    t.send(True, smb2_close())
    t.send(False, smb2_close_response())
    t.close()
    # SMTP with a MIME attachment
    t = Tcp(w, c, "10.1.0.25", 45300, 25).open()
    t.send(False, b"220 mx ESMTP\r\n")
    t.send(True, b"EHLO pf\r\n")
    t.send(False, b"250 mx\r\n")
    t.send(True, b"MAIL FROM:<alice@example.com>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"RCPT TO:<bob@example.org>\r\n")
    t.send(False, b"250 OK\r\n")
    t.send(True, b"DATA\r\n")
    t.send(False, b"354 go\r\n")
    t.send(True, _mime_mail() + b".\r\n")
    t.send(False, b"250 queued\r\n")
    t.send(True, b"QUIT\r\n")
    t.close()
    # POP3 RETR of the same mail
    t = Tcp(w, c, "10.1.0.110", 45400, 110).open()
    t.send(False, b"+OK POP3 ready\r\n")
    t.send(True, b"USER bob\r\n")
    t.send(False, b"+OK\r\n")
    t.send(True, b"PASS secret\r\n")
    t.send(False, b"+OK logged in\r\n")
    t.send(True, b"RETR 1\r\n")
    t.send(False, b"+OK message follows\r\n" + _mime_mail().replace(b"logo.png", b"pop-logo.png") + b".\r\n")
    t.send(True, b"QUIT\r\n")
    t.close()
    # IMAP FETCH of the mail with a literal
    t = Tcp(w, c, "10.1.0.143", 45500, 143).open()
    msg = _mime_mail().replace(b"logo.png", b"imap-logo.png")
    t.send(False, b"* OK IMAP ready\r\n")
    t.send(True, b"a1 LOGIN bob secret\r\n")
    t.send(False, b"a1 OK logged in\r\n")
    t.send(True, b"a2 FETCH 1 BODY[]\r\n")
    t.send(False, b"* 1 FETCH (BODY[] {" + str(len(msg)).encode() + b"}\r\n" + msg + b")\r\na2 OK done\r\n")
    t.send(True, b"a3 LOGOUT\r\n")
    t.close()
    return w.write()


def smb2_write(data: bytes, *, tree: int = 1, msg_id: int = 5, session: int = 0x100, fid: bytes = b"\x01" * 16) -> bytes:
    body = struct.pack("<HHIQ16sIIHHI", 49, 112, len(data), 0, fid, 0, 0, 0, 0, 0) + data
    return smb2_message(9, body, msg_id=msg_id, tree=tree, session=session)


def smb2_write_response(count: int, *, tree: int = 1, msg_id: int = 5, session: int = 0x100) -> bytes:
    return smb2_message(9, struct.pack("<HHIIHH", 17, 0, count, 0, 0, 0) + b"\x00", response=True, msg_id=msg_id,
                        tree=tree, session=session)


def smb2_close(*, tree: int = 1, msg_id: int = 6, session: int = 0x100, fid: bytes = b"\x01" * 16) -> bytes:
    return smb2_message(6, struct.pack("<HHI16s", 24, 0, 0, fid), msg_id=msg_id, tree=tree, session=session)


def smb2_close_response(*, tree: int = 1, msg_id: int = 6, session: int = 0x100) -> bytes:
    return smb2_message(6, struct.pack("<HHIQQQQQQI", 60, 0, 0, 0, 0, 0, 0, 0, 0, 0x80), response=True, msg_id=msg_id,
                        tree=tree, session=session)


def smb1_negotiate_request() -> bytes:
    header = b"\xffSMB" + bytes([0x72]) + struct.pack("<IBHH", 0, 0x18, 0xC853, 0) + bytes(8) + struct.pack("<HHHHH", 0, 0, 1, 0, 1)
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    pdu = header + body
    return b"\x00" + struct.pack(">I", len(pdu))[1:] + pdu


@fixture("smb_attack.pcap")
def fixture_smb_attack() -> bytes:
    """SMBv1 negotiation, then an anonymous SMB2 session that reaches ADMIN$ and writes a service binary (#204)."""
    w = Wire(start=1_700_300_000.0)
    c, s = "10.2.0.9", "10.2.0.40"
    Tcp(w, c, s, 46000, 445).open().send(True, smb1_negotiate_request()).close()
    t = Tcp(w, c, s, 46100, 445).open()
    t.send(True, smb2_negotiate_request())
    t.send(False, smb2_negotiate_response())
    t.send(True, smb2_session_setup(ntlm_negotiate(), msg_id=1))
    t.send(False, smb2_session_setup(ntlm_challenge(bytes(8)), response=True, msg_id=1, session=0x100, status=0xC0000016))
    t.send(True, smb2_session_setup(ntlm_authenticate("", "", "", b"", lm_response=b"\x00"), msg_id=2, session=0x100))
    t.send(False, smb2_session_setup(b"", response=True, msg_id=2, session=0x100))
    t.send(True, smb2_tree_connect("\\\\10.2.0.40\\ADMIN$"))
    t.send(False, smb2_tree_connect_response())
    t.send(True, smb2_create("PSEXESVC.exe"))
    t.send(False, smb2_create_response())
    t.send(True, smb2_tree_connect("\\\\10.2.0.40\\IPC$", msg_id=7))
    t.send(False, smb2_tree_connect_response(tree=2, msg_id=7))
    t.send(True, smb2_create("svcctl", tree=2, msg_id=8))
    t.send(False, smb2_create_response(tree=2, msg_id=8))
    t.close()
    return w.write()
