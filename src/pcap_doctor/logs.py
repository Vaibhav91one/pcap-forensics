"""Zeek-style per-protocol logs (TSV or JSON): conn, dns, http, ssl, x509, files, notice, weird, dhcp, ftp, smtp,
ssh, smb (issue #199).

The tables are built on demand from the :class:`CaptureIndex` plus a few extra tshark passes (``conn``, ``dhcp``,
``ftp``, ``smtp``, ``smb``, ``weird``) that ``analyze`` never runs. The column names and types follow Zeek's, so
``zeek-cut``, Brim and the usual SIEM parsers read them. Where tshark cannot supply what Zeek knows (a TCP
``history`` string is approximated from the flags, payload bytes come from the TCP/UDP length fields) the column
says so in ``docs/zeek-logs.md`` rather than guessing.

Secrets stay out: FTP ``PASS`` arguments, HTTP credentials and SMTP AUTH data are never written.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from .data_ciphers import registry
from .index import CaptureIndex, first, many
from .models import flow_key, stable_id
from .prompts import clean_capture_text
from .tshark import Row, to_float, to_int

Column = tuple[str, str]  # (zeek field name, zeek type)


@dataclass
class LogTable:
    name: str
    columns: list[Column]
    rows: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------- context
class _Ctx:
    def __init__(self, index: CaptureIndex) -> None:
        if index.runner is None:
            raise ValueError("this index was not built by IndexBuilder; no tshark runner to read more passes from")
        self.index = index
        self.runner = index.runner
        self.times: dict[int, float] = {}
        for row in self.runner.run("base"):
            n, t = to_int(first(row, "frame.number")), to_float(first(row, "frame.time_epoch"))
            if n is not None and t is not None:
                self.times[n] = t
        self._conn: dict[str, _Conn] | None = None

    def ts(self, frame: int | None) -> float | None:
        return self.times.get(frame) if frame else None

    @property
    def conns(self) -> dict[str, _Conn]:
        if self._conn is None:
            self._conn = _read_conns(self.runner.run("conn"))
        return self._conn

    def ids(self, key: str) -> dict[str, Any]:
        """``uid`` and the four ``id.*`` columns for a (canonical) flow key; originator first, like Zeek."""
        conn = self.conns.get(key)
        if conn:
            return conn.ids()
        _proto, a, ap, b, bp = _endpoints(key)
        return {"uid": _uid(key), "id.orig_h": a, "id.orig_p": ap, "id.resp_h": b, "id.resp_p": bp}

    def row_key(self, row: Row, proto: str) -> str | None:
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        sp = to_int(first(row, f"{proto}.srcport"))
        dp = to_int(first(row, f"{proto}.dstport"))
        if not src or not dst or sp is None or dp is None:
            return None
        return flow_key(proto, src, sp, dst, dp)


def _endpoints(key: str) -> tuple[str, str, int, str, int]:
    from .models import endpoints_of

    return endpoints_of(key)


def _uid(key: str) -> str:
    return "C" + stable_id("uid", key)[:16]


ID_COLS: list[Column] = [
    ("uid", "string"), ("id.orig_h", "addr"), ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
]


@dataclass
class _Conn:
    key: str
    proto: str
    orig: tuple[str, int]
    resp: tuple[str, int]
    first_ts: float = 0.0
    last_ts: float = 0.0
    pkts: list[int] = field(default_factory=lambda: [0, 0])
    payload: list[int] = field(default_factory=lambda: [0, 0])
    ip_bytes: list[int] = field(default_factory=lambda: [0, 0])
    syn: list[int] = field(default_factory=lambda: [0, 0])
    synack: list[int] = field(default_factory=lambda: [0, 0])
    fin: list[int] = field(default_factory=lambda: [0, 0])
    rst: list[int] = field(default_factory=lambda: [0, 0])
    history: list[str] = field(default_factory=list)

    def ids(self) -> dict[str, Any]:
        return {"uid": _uid(self.key), "id.orig_h": self.orig[0], "id.orig_p": self.orig[1],
                "id.resp_h": self.resp[0], "id.resp_p": self.resp[1]}

    def state(self) -> str:
        """Zeek's connection state, from the flag counts of both sides (index 0 = originator)."""
        if self.proto == "udp":
            return "SF" if self.pkts[1] else "S0"
        o_syn, r_synack = self.syn[0] > 0, self.synack[1] > 0
        if not o_syn:
            return "OTH"
        if not r_synack:
            if self.rst[1]:
                return "REJ"
            return "RSTOS0" if self.rst[0] else "S0"
        if self.rst[0]:
            return "RSTO"
        if self.rst[1]:
            return "RSTR"
        if self.fin[0] and self.fin[1]:
            return "SF"
        if self.fin[0]:
            return "S2"
        if self.fin[1]:
            return "S3"
        return "S1"


def _read_conns(rows: list[Row]) -> dict[str, _Conn]:
    conns: dict[str, _Conn] = {}
    for row in rows:
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        sp, dp = to_int(first(row, f"{proto}.srcport")), to_int(first(row, f"{proto}.dstport"))
        if not src or not dst or sp is None or dp is None:
            continue
        key = flow_key(proto, src, sp, dst, dp)
        ts = to_float(first(row, "frame.time_epoch")) or 0.0
        conn = conns.get(key)
        if conn is None:
            conn = conns[key] = _Conn(key, proto, (src, sp), (dst, dp), ts, ts)
        side = 0 if (src, sp) == conn.orig else 1
        conn.last_ts = max(conn.last_ts, ts)
        conn.pkts[side] += 1
        if proto == "tcp":
            payload = to_int(first(row, "tcp.len")) or 0
        else:
            payload = max(0, (to_int(first(row, "udp.length")) or 8) - 8)
        conn.payload[side] += payload
        ip_len = to_int(first(row, "ip.len"))
        if ip_len is None:
            ip_len = (to_int(first(row, "ipv6.plen")) or 0) + 40
        conn.ip_bytes[side] += ip_len
        if proto != "tcp":
            continue
        syn, ack = first(row, "tcp.flags.syn") in ("1", "True"), first(row, "tcp.flags.ack") in ("1", "True")
        fin, rst = first(row, "tcp.flags.fin") in ("1", "True"), first(row, "tcp.flags.reset") in ("1", "True")
        letters = []
        if syn and not ack:
            conn.syn[side] += 1
            letters.append("S")
        elif syn:
            conn.synack[side] += 1
            letters.append("H")
        if fin:
            conn.fin[side] += 1
            letters.append("F")
        if rst:
            conn.rst[side] += 1
            letters.append("R")
        if not (syn or fin or rst):
            letters.append("D" if payload else "A")
        for letter in letters:
            letter = letter if side == 0 else letter.lower()
            if not conn.history or conn.history[-1] != letter:  # repeated ACK / data packets collapse to one letter
                conn.history.append(letter)
    return conns


# ---------------------------------------------------------------------------- builders
_SERVICE = {"tls": "ssl", "dtls": "dtls", "http": "http", "dns": "dns", "ssh": "ssh", "ftp": "ftp", "smtp": "smtp",
            "smb": "smb", "smb2": "smb", "dhcp": "dhcp", "ntp": "ntp", "snmp": "snmp", "telnet": "telnet",
            "ldap": "ldap", "sip": "sip", "quic": "quic", "mysql": "mysql", "modbus": "modbus", "mqtt": "mqtt"}

_PORT_SERVICE = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 67: "dhcp", 80: "http", 123: "ntp", 161: "snmp",
                 389: "ldap", 443: "ssl", 445: "smb", 502: "modbus", 1883: "mqtt", 5060: "sip", 8080: "http"}

CONN_COLS: list[Column] = [
    ("ts", "time"), *ID_COLS, ("proto", "enum"), ("service", "string"), ("duration", "interval"),
    ("orig_bytes", "count"), ("resp_bytes", "count"), ("conn_state", "string"), ("missed_bytes", "count"),
    ("history", "string"), ("orig_pkts", "count"), ("orig_ip_bytes", "count"), ("resp_pkts", "count"),
    ("resp_ip_bytes", "count"),
]


def _conn_log(ctx: _Ctx) -> LogTable:
    table = LogTable("conn", CONN_COLS)
    for key, c in sorted(ctx.conns.items(), key=lambda kv: (kv[1].first_ts, kv[0])):
        flow = ctx.index.flows.get(key)
        table.rows.append({
            "ts": c.first_ts, **c.ids(), "proto": c.proto,
            "service": (_SERVICE.get(flow.app_proto) if flow else None) or _PORT_SERVICE.get(c.resp[1]),
            "duration": round(c.last_ts - c.first_ts, 6), "orig_bytes": c.payload[0], "resp_bytes": c.payload[1],
            "conn_state": c.state(), "missed_bytes": 0, "history": "".join(c.history) or None,
            "orig_pkts": c.pkts[0], "orig_ip_bytes": c.ip_bytes[0], "resp_pkts": c.pkts[1],
            "resp_ip_bytes": c.ip_bytes[1],
        })
    return table


_QTYPES = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA",
           "33": "SRV", "43": "DS", "46": "RRSIG", "48": "DNSKEY", "65": "HTTPS", "255": "*"}
_RCODES = {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED"}


def _dns_log(ctx: _Ctx) -> LogTable:
    table = LogTable("dns", [
        ("ts", "time"), *ID_COLS, ("proto", "enum"), ("query", "string"), ("qtype_name", "string"),
        ("rcode_name", "string"), ("answers", "vector[string]"), ("rejected", "bool")])
    for q in ctx.index.dns:
        if q.is_response:
            continue
        rcode = q.rcode
        table.rows.append({
            "ts": ctx.ts(q.frame), **ctx.ids(q.key), "proto": q.key.split(":", 1)[0], "query": q.name,
            "qtype_name": _QTYPES.get(q.qtype, q.qtype),
            "rcode_name": _RCODES.get(rcode, rcode) if rcode is not None else None, "answers": q.answers or None,
            "rejected": None if rcode is None else _RCODES.get(rcode, rcode) != "NOERROR",
        })
    return table


def _http_log(ctx: _Ctx) -> LogTable:
    table = LogTable("http", [
        ("ts", "time"), *ID_COLS, ("method", "string"), ("host", "string"), ("uri", "string"), ("version", "string"),
        ("user_agent", "string"), ("status_code", "count"), ("resp_mime_types", "vector[string]"),
        ("resp_filenames", "vector[string]"), ("auth_scheme", "string"), ("encrypted", "bool")])
    for h in ctx.index.http:
        table.rows.append({
            "ts": ctx.ts(h.frame), **ctx.ids(h.key), "method": h.method, "host": h.host, "uri": h.uri,
            "version": h.version, "user_agent": h.user_agent, "status_code": h.status,
            "resp_mime_types": h.content_types or None, "resp_filenames": h.download_names or None,
            "auth_scheme": h.auth_scheme, "encrypted": h.is_encrypted,
        })
    return table


def _fuid(*parts: object) -> str:
    return "F" + stable_id(*parts)[:16]


def _ssl_log(ctx: _Ctx) -> LogTable:
    suites = registry()
    table = LogTable("ssl", [
        ("ts", "time"), *ID_COLS, ("version", "string"), ("cipher", "string"), ("curve", "string"),
        ("server_name", "string"), ("resumed", "bool"), ("next_protocol", "string"), ("established", "bool"),
        ("cert_chain_fuids", "vector[string]"), ("ja3", "string"), ("ja3s", "string")])
    for s in ctx.index.tls.values():
        suite = suites.get(s.chosen_cipher) if s.chosen_cipher is not None else None
        table.rows.append({
            "ts": ctx.ts(s.frames[0] if s.frames else None), **ctx.ids(s.key), "version": s.negotiated_version,
            "cipher": suite.name if suite else None, "curve": s.groups[0] if s.groups else None,
            "server_name": s.sni, "resumed": s.resumption, "next_protocol": s.alpn[0] if s.alpn else None,
            "established": s.complete, "cert_chain_fuids": [_fuid(s.key, c.chain_index) for c in s.certs] or None,
            "ja3": s.ja3, "ja3s": s.ja3s,
        })
    return table


def _x509_log(ctx: _Ctx) -> LogTable:
    table = LogTable("x509", [
        ("ts", "time"), ("id", "string"), ("certificate.subject", "string"), ("certificate.issuer", "string"),
        ("certificate.not_valid_before", "string"), ("certificate.not_valid_after", "string"),
        ("certificate.key_alg", "string"), ("certificate.key_length", "count"), ("certificate.sig_alg", "string"),
        ("certificate.curve", "string"), ("san.dns", "vector[string]"), ("spki_sha256", "string")])
    for s in ctx.index.tls.values():
        for c in s.certs:
            table.rows.append({
                "ts": ctx.ts(c.frame), "id": _fuid(s.key, c.chain_index), "certificate.subject": c.subject,
                "certificate.issuer": c.issuer, "certificate.not_valid_before": c.not_before,
                "certificate.not_valid_after": c.not_after, "certificate.key_alg": c.key_algorithm,
                "certificate.key_length": c.public_key_bits, "certificate.sig_alg": c.signature_algorithm_oid,
                "certificate.curve": c.key_curve, "san.dns": c.san_dns or None, "spki_sha256": c.spki_sha256,
            })
    return table


def _ssh_log(ctx: _Ctx) -> LogTable:
    table = LogTable("ssh", [
        ("ts", "time"), *ID_COLS, ("version", "count"), ("client", "string"), ("server", "string"),
        ("cipher_alg", "string"), ("mac_alg", "string"), ("compression_alg", "string"), ("kex_alg", "string"),
        ("host_key_alg", "string")])
    for s in ctx.index.ssh:
        table.rows.append({
            "ts": ctx.ts(s.frame), **ctx.ids(s.key), "version": 2, "client": s.client_version,
            "server": s.server_version, "cipher_alg": s.ciphers[0] if s.ciphers else None,
            "mac_alg": s.macs[0] if s.macs else None, "compression_alg": s.compression[0] if s.compression else None,
            "kex_alg": s.kex_algorithms[0] if s.kex_algorithms else None,
            "host_key_alg": s.host_key_algorithms[0] if s.host_key_algorithms else None,
        })
    return table


def _files_log(ctx: _Ctx) -> LogTable:
    """Every file the extractor recovers (HTTP, FTP, SMB, TFTP, mail), hashed and typed by magic bytes."""
    import tempfile

    from .extract import extract, safe_name

    table = LogTable("files", [
        ("ts", "time"), ("fuid", "string"), ("tx_hosts", "set[addr]"), ("rx_hosts", "set[addr]"),
        ("conn_uids", "set[string]"), ("source", "string"), ("mime_type", "string"), ("filename", "string"),
        ("seen_bytes", "count"), ("md5", "string"), ("sha1", "string"), ("sha256", "string")])
    exchanges = {safe_name((h.uri or "").split("?", 1)[0]): h for h in ctx.index.http if h.status and h.uri}
    with tempfile.TemporaryDirectory() as tmp:
        for f in extract(ctx.index.capture_path, Path(tmp)):
            if f.info is None:
                continue
            row: dict[str, Any] = {
                "ts": None, "fuid": _fuid(f.protocol, f.info.sha256, f.name), "source": f.protocol.upper(),
                "mime_type": f.info.mime_type, "filename": f.name, "seen_bytes": f.info.size, "md5": f.info.md5,
                "sha1": f.info.sha1, "sha256": f.info.sha256,
            }
            h = exchanges.get(safe_name(f.name)) if f.protocol == "http" else None
            if h:
                ids = ctx.ids(h.key)
                row.update(ts=ctx.ts(h.frame), tx_hosts=[ids["id.resp_h"]], rx_hosts=[ids["id.orig_h"]],
                           conn_uids=[ids["uid"]])
            table.rows.append(row)
    return table


def _notice_log(ctx: _Ctx) -> LogTable:
    from .registry import enabled_detectors

    table = LogTable("notice", [
        ("ts", "time"), *ID_COLS, ("note", "string"), ("msg", "string"), ("sub", "string"), ("severity", "string")])
    for detector in enabled_detectors():
        try:
            found = detector.detect(ctx.index)
        except Exception:  # one bad detector must not sink the logs, as in the pipeline
            continue
        for f in found:
            frame = f.evidence[0].frame if f.evidence else None
            table.rows.append({
                "ts": ctx.ts(frame), **(ctx.ids(f.flow_key) if f.flow_key else {}), "note": f.code,
                "msg": f.title, "sub": f.summary[:200], "severity": f.severity,
            })
    table.rows.sort(key=lambda r: (r["ts"] is None, r["ts"] or 0.0, r["note"]))
    return table


_SEVERITY = {0x600000: "warn", 0x800000: "error"}


def _slug(message: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", message.lower()).strip("_")[:80]


def _weird_log(ctx: _Ctx) -> LogTable:
    table = LogTable("weird", [("ts", "time"), *ID_COLS, ("name", "string"), ("addl", "string"), ("severity", "string")])
    for row in ctx.runner.run("weird"):
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        key = ctx.row_key(row, proto)
        ts = to_float(first(row, "frame.time_epoch"))
        ids = ctx.ids(key) if key else {}
        for message, sev in zip(many(row, "_ws.expert.message"), many(row, "_ws.expert.severity"), strict=False):
            level = _SEVERITY.get(to_int(sev) or 0)
            if level:
                table.rows.append({"ts": ts, **ids, "name": _slug(message), "addl": message, "severity": level})
    return table


_DHCP_TYPES = {"1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE", "5": "ACK", "6": "NAK",
               "7": "RELEASE", "8": "INFORM"}


def _dhcp_log(ctx: _Ctx) -> LogTable:
    table = LogTable("dhcp", [
        ("ts", "time"), ("uids", "set[string]"), ("client_addr", "addr"), ("server_addr", "addr"), ("mac", "string"),
        ("host_name", "string"), ("domain", "string"), ("requested_addr", "addr"), ("assigned_addr", "addr"),
        ("lease_time", "interval"), ("msg_types", "vector[string]"), ("vendor_class", "string")])
    by_xid: dict[str, dict[str, Any]] = {}
    for row in ctx.runner.run("dhcp"):
        xid = first(row, "dhcp.id") or str(len(by_xid))
        t = _DHCP_TYPES.get(first(row, "dhcp.option.dhcp"))
        proto = "udp"
        key = ctx.row_key(row, proto)
        r = by_xid.setdefault(xid, {"ts": to_float(first(row, "frame.time_epoch")), "uids": [], "msg_types": []})
        if key:
            uid = ctx.ids(key)["uid"]
            if uid not in r["uids"]:
                r["uids"].append(uid)
        if t:
            r["msg_types"].append(t)
        client_ip = first(row, "dhcp.ip.client")
        if client_ip and client_ip != "0.0.0.0":
            r["client_addr"] = client_ip
        server = first(row, "dhcp.option.dhcp_server_id")
        if server:
            r["server_addr"] = server
        for src, dst in (("dhcp.hw.mac_addr", "mac"), ("dhcp.option.hostname", "host_name"),
                         ("dhcp.option.domain_name", "domain"), ("dhcp.option.requested_ip_address", "requested_addr"),
                         ("dhcp.option.vendor_class_id", "vendor_class")):
            if first(row, src):
                r[dst] = first(row, src)
        yiaddr = first(row, "dhcp.ip.your")
        if yiaddr and yiaddr != "0.0.0.0" and t in ("ACK", "OFFER"):
            r["assigned_addr"] = r.get("assigned_addr") if t == "OFFER" and "assigned_addr" in r else yiaddr
        lease = to_float(first(row, "dhcp.option.ip_address_lease_time"))
        if lease is not None:
            r["lease_time"] = lease
    table.rows = [r for r in by_xid.values() if r["msg_types"]]
    return table


def _ftp_log(ctx: _Ctx) -> LogTable:
    table = LogTable("ftp", [
        ("ts", "time"), *ID_COLS, ("user", "string"), ("command", "string"), ("arg", "string"),
        ("reply_code", "count"), ("reply_msg", "string")])
    pending: dict[str, dict[str, Any]] = {}
    user: dict[str, str] = {}
    for row in ctx.runner.run("ftp"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        stream = first(row, "tcp.stream") or key
        cmd = first(row, "ftp.request.command")
        code = to_int(first(row, "ftp.response.code"))
        if cmd:
            arg = first(row, "ftp.request.arg")
            if cmd.upper() == "USER":
                user[stream] = arg
            if cmd.upper() == "PASS":
                arg = "<hidden>"
            rec = {"ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key), "user": user.get(stream),
                   "command": cmd, "arg": arg}
            pending[stream] = rec
            table.rows.append(rec)
        elif code is not None and stream in pending and "reply_code" not in pending[stream]:
            pending[stream]["reply_code"] = code
            pending[stream]["reply_msg"] = first(row, "ftp.response.arg")
    return table


def _smtp_log(ctx: _Ctx) -> LogTable:
    table = LogTable("smtp", [
        ("ts", "time"), *ID_COLS, ("trans_depth", "count"), ("helo", "string"), ("mailfrom", "string"),
        ("rcptto", "set[string]"), ("date", "string"), ("from", "string"), ("to", "set[string]"),
        ("subject", "string"), ("msg_id", "string"), ("last_reply", "string")])
    cur: dict[str, dict[str, Any]] = {}
    helo: dict[str, str] = {}
    depth: dict[str, int] = defaultdict(int)

    def clean_addr(v: str) -> str:
        return v.strip().strip("<>").split(":", 1)[-1].strip().strip("<>") if v else v

    for row in ctx.runner.run("smtp"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        stream = first(row, "tcp.stream") or key
        cmd = first(row, "smtp.req.command").upper()
        param = first(row, "smtp.req.parameter")
        code = first(row, "smtp.response.code")
        tx = cur.get(stream)
        if cmd in ("HELO", "EHLO"):
            helo[stream] = param
        elif cmd == "MAIL":
            depth[stream] += 1
            tx = cur[stream] = {"ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key),
                                "trans_depth": depth[stream], "helo": helo.get(stream), "mailfrom": clean_addr(param),
                                "rcptto": []}
            table.rows.append(tx)
        elif cmd == "RCPT" and tx is not None:
            tx["rcptto"].append(clean_addr(param))
        if first(row, "imf.from") and tx is not None:
            tx["from"] = first(row, "imf.from")
            tx["to"] = many(row, "imf.to") or None
            tx["subject"] = first(row, "imf.subject") or None
            tx["date"] = first(row, "imf.date") or None
            tx["msg_id"] = first(row, "imf.message_id") or None
        if code and tx is not None:
            tx["last_reply"] = f"{code} {first(row, 'smtp.rsp.parameter')}".strip()
    for r in table.rows:
        r["rcptto"] = r["rcptto"] or None
    return table


_SMB2_CMDS = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT", 5: "CREATE",
              6: "CLOSE", 7: "FLUSH", 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO",
              14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK"}


def _smb_log(ctx: _Ctx) -> LogTable:
    table = LogTable("smb", [
        ("ts", "time"), *ID_COLS, ("version", "string"), ("command", "string"), ("response", "bool"),
        ("status", "string"), ("tree", "string"), ("filename", "string"), ("username", "string"),
        ("domain", "string"), ("hostname", "string")])
    for row in ctx.runner.run("smb"):
        key = ctx.row_key(row, "tcp")
        if not key:
            continue
        cmds = many(row, "smb2.cmd")
        version = "SMB2" if cmds or first(row, "smb2.sesid") else "SMB1"
        names = [_SMB2_CMDS.get(n, f"CMD_{c}") if (n := to_int(c)) is not None else f"CMD_{c}" for c in cmds] or [
            f"CMD_{c}" for c in many(row, "smb.cmd")]
        responses = many(row, "smb2.flags.response")
        for i, name in enumerate(names or ["?"]):
            table.rows.append({
                "ts": to_float(first(row, "frame.time_epoch")), **ctx.ids(key), "version": version, "command": name,
                "response": (responses[i] if i < len(responses) else (responses[0] if responses else "")) in ("1", "True") if responses else None,
                "status": first(row, "smb2.nt_status") or first(row, "smb.nt_status") or None,
                "tree": first(row, "smb2.tree") or None,
                "filename": first(row, "smb2.filename") or first(row, "smb.file") or None,
                "username": first(row, "ntlmssp.auth.username") or None,
                "domain": first(row, "ntlmssp.auth.domain") or None,
                "hostname": first(row, "ntlmssp.auth.hostname") or None,
            })
    return table


BUILDERS: dict[str, Callable[[_Ctx], LogTable]] = {
    "conn": _conn_log, "dns": _dns_log, "http": _http_log, "ssl": _ssl_log, "x509": _x509_log, "files": _files_log,
    "notice": _notice_log, "weird": _weird_log, "dhcp": _dhcp_log, "ftp": _ftp_log, "smtp": _smtp_log,
    "ssh": _ssh_log, "smb": _smb_log,
}
LOG_NAMES = tuple(BUILDERS)


def build_logs(index: CaptureIndex, names: tuple[str, ...] = ()) -> dict[str, LogTable]:
    unknown = [n for n in names if n not in BUILDERS]
    if unknown:
        raise ValueError(f"unknown log(s) {', '.join(unknown)}; logs: {', '.join(LOG_NAMES)}")
    ctx = _Ctx(index)
    return {n: BUILDERS[n](ctx) for n in (names or LOG_NAMES)}


#: Cached per index: the sources registered with the query language build a table once per run.
def log_rows(index: CaptureIndex, name: str) -> list[dict[str, Any]]:
    return build_logs(index, (name,))[name].rows


# ---------------------------------------------------------------------------- writers
def _tsv_value(value: Any, ztype: str) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "T" if value else "F"
    if isinstance(value, list):
        text = ",".join(str(v) for v in value)
        return text or "(empty)"
    if ztype in ("time", "interval") and isinstance(value, float):
        return f"{value:.6f}"
    text = clean_capture_text(str(value), 2000)
    # the field separator and the set separator must not occur inside a value
    text = text.replace(",", "\\x2c") if ztype.startswith(("set", "vector")) else text
    return text if text != "" else "(empty)"


def write_tsv(table: LogTable, outdir: Path, first_ts: float, last_ts: float) -> Path:
    from datetime import UTC, datetime

    def stamp(t: float) -> str:
        return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d-%H-%M-%S")

    path = outdir / f"{table.name}.log"
    lines = [
        "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", f"#path\t{table.name}",
        f"#open\t{stamp(first_ts)}", "#fields\t" + "\t".join(n for n, _ in table.columns),
        "#types\t" + "\t".join(t for _, t in table.columns),
    ]
    for row in table.rows:
        lines.append("\t".join(_tsv_value(row.get(n), t) for n, t in table.columns))
    lines.append(f"#close\t{stamp(last_ts)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _json_value(value: Any) -> Any:
    return clean_capture_text(value, 2000) if isinstance(value, str) else value


def write_json(table: LogTable, outdir: Path) -> Path:
    path = outdir / f"{table.name}.json.log"
    with path.open("w", encoding="utf-8") as fh:
        for row in table.rows:
            fh.write(json.dumps({n: _json_value(row[n]) for n, _ in table.columns if row.get(n) is not None},
                                ensure_ascii=False) + "\n")
    return path


def write_logs(tables: dict[str, LogTable], outdir: Path, fmt: str, first_ts: float, last_ts: float) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for table in tables.values():
        if fmt in ("tsv", "both"):
            written.append(write_tsv(table, outdir, first_ts, last_ts))
        if fmt in ("json", "both"):
            written.append(write_json(table, outdir))
    return written


def register_query_sources() -> None:
    """Make every log table queryable (``query CAPTURE EXPR -s conn``)."""
    from .query import SOURCES

    for name in LOG_NAMES:
        SOURCES.setdefault(f"log:{name}", partial(log_rows, name=name))
