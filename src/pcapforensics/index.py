"""CaptureIndex: the single, frozen view of a capture that detectors read.

Phase 0 owns this module. Detector subagents must not edit it -- if a field is
missing, file an issue and the core owner extends the model (AGENTS.md ->
"Schema freeze").
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .certificates import CertFacts, apply_openssl_facts, enrich_all
from .models import (
    CaptureInfo,
    Cert,
    DnsQuery,
    Finding,
    Flow,
    Handshake,
    Host,
    HttpExchange,
    QuicSession,
    Role,
    RtpStream,
    ServiceHit,
    SipMessage,
    SshSession,
    Stats,
    TlsAlert,
    TlsSession,
    endpoints_of,
    flow_key,
)
from .tshark import (
    SERVICE_FIELDS,
    Row,
    TsharkRunner,
    parse_cipher_ids,
    public_key_bits,
    to_bool01,
    to_float,
    to_int,
    to_int_auto,
    to_int_list,
    tshark_version,
)

VERSION_HEX_RE = re.compile(r"0x([0-9a-fA-F]{4})")

VERSION_NAMES: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x7F00: "TLS 1.3 (draft)",
    0x7F01: "TLS 1.3 (draft)",
    0x7F02: "TLS 1.3 (draft)",
    0x7F03: "TLS 1.3 (draft)",
    0x7F04: "TLS 1.3 (draft)",
    0x0100: "DTLS 1.0",  # OpenSSL < 0.9.8f encodes DTLS 1.0 as 0x0100
    0xFEFF: "DTLS 1.0",
    0xFEFD: "DTLS 1.2",
    0xFEFC: "DTLS 1.3",
}

PROTO_ALIASES: dict[str, str] = {
    "tls": "tls",
    "ssl": "tls",
    "dtls": "dtls",
    "http": "http",
    "http2": "http2",
    "dns": "dns",
    "mdns": "mdns",
    "quic": "quic",
    "sip": "sip",
    "sdp": "sdp",
    "rtp": "rtp",
    "ssh": "ssh",
    "ftp": "ftp",
    "ftp-data": "ftp-data",
    "telnet": "telnet",
    "snmp": "snmp",
    "ldap": "ldap",
    "smtp": "smtp",
    "imap": "imap",
    "pop3": "pop3",
    "ntp": "ntp",
    "tftp": "tftp",
    "redis": "redis",
    "mysql": "mysql",
    "arp": "arp",
    "icmp": "icmp",
    "tcp": "tcp",
    "udp": "udp",
    "data": "data",
}

SENSITIVE_SERVICES: dict[str, bool] = {
    "ftp": True,
    "telnet": True,
    "tftp": True,
    "ntp": True,
    "snmp": True,
    "ldap": True,
    "smtp": True,
    "imap": True,
    "pop3": True,
    "redis": True,
    "mysql": True,
    "http": True,
}

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1194: "openvpn",
    1900: "ssdp",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5061: "sips",
    5222: "xmpp-client",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
}

#: A packet arrives more than this many seconds after the previous packet of the
#: same flow, it starts a new burst (issue #10).
BURST_GAP_S = 1.0

GREASE_VALUES: frozenset[int] = frozenset(
    value for value in range(0x10000) if (value & 0x0F0F) == 0x0A0A and (value >> 8) & 0xFF == (value & 0xFF)
)

NON_CIPHER_VALUES: frozenset[int] = frozenset(
    {0x0000, 0x00FF} | {v for v in GREASE_VALUES if v}
)


def version_name(hex_or_int: str | int | None) -> str | None:
    if hex_or_int is None:
        return None
    if isinstance(hex_or_int, int):
        return VERSION_NAMES.get(hex_or_int, f"0x{hex_or_int:04x}")
    match = VERSION_HEX_RE.search(hex_or_int)
    if not match:
        return hex_or_int or None
    value = int(match.group(1), 16)
    return VERSION_NAMES.get(value, f"0x{value:04x}")


def first(row: Row, field: str, default: str = "") -> str:
    values = row.get(field)
    if not values:
        return default
    return values[0]


def many(row: Row, field: str) -> list[str]:
    out: list[str] = []
    for chunk in row.get(field, []):
        out.extend(part for part in chunk.split(",") if part)
    return out


def normalize_version_list(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        name = version_name(value.strip())
        if name and name not in out:
            out.append(name)
    return out


#: Layers that describe the transport, not the application.
TRANSPORT_LAYERS = {"tcp", "udp", "ip", "ipv6", "eth", "ethertype", "data", "arp", "icmp", "ip-udp"}


def app_proto_from(protocols: str) -> str:
    """Application layer implied by a frame's protocol stack.

    ``eth:ethertype:ip:tcp`` is TCP, not "ethernet" -- getting this wrong made
    every plain conversation look like an unknown service.
    """
    layers = [p for p in protocols.split(":") if p]
    for layer in reversed(layers):
        canonical = PROTO_ALIASES.get(layer)
        if canonical and canonical not in TRANSPORT_LAYERS:
            return canonical
    for layer in reversed(layers):
        canonical = PROTO_ALIASES.get(layer)
        if canonical in {"tcp", "udp"}:
            return canonical
    for layer in ("arp", "icmp", "ipv6", "eth", "ethertype", "data"):
        if layer in layers:
            return PROTO_ALIASES.get(layer, layer)
    return layers[-1] if layers else "unknown"


class CaptureIndex:
    """Everything a detector is allowed to look at."""

    def __init__(self, capture: CaptureInfo) -> None:
        self.capture = capture
        self.flows: dict[str, Flow] = {}
        self.hosts: dict[str, Host] = {}
        self.tls: dict[str, TlsSession] = {}
        self.http: list[HttpExchange] = []
        self.dns: list[DnsQuery] = []
        self.sip: list[SipMessage] = []
        self.rtp: list[RtpStream] = []
        self.ssh: list[SshSession] = []
        self.quic: list[QuicSession] = []
        self.services: list[ServiceHit] = []
        self.notes: list[str] = []
        self.dropped_fields: list[str] = []
        self.pass_stats: dict[str, dict[str, int | float | str]] = {}
        self._flow_by_pair: dict[tuple[str, int], str] = {}

    # -- lookups -----------------------------------------------------------
    def flow(self, key: str) -> Flow | None:
        return self.flows.get(key)

    def flow_by(self, ip: str, port: int | None = None) -> Flow | None:
        if port is None:
            for flow in self.flows.values():
                if flow.matches_endpoint(ip):
                    return flow
            return None
        return self.flows.get(self._flow_by_pair.get((ip, port), ""))

    def flows_touching(self, ip: str) -> list[Flow]:
        return [f for f in self.flows.values() if f.matches_endpoint(ip)]

    def flows_with_app(self, *apps: str) -> list[Flow]:
        wanted = set(apps)
        return [f for f in self.flows.values() if f.app_proto in wanted]

    def is_encrypted(self, key: str) -> bool | None:
        flow = self.flows.get(key)
        return flow.encrypted if flow else None

    def iter_endpoints(self) -> Iterable[tuple[str, str, int, str, int, str]]:
        for key in self.flows:
            proto, a, ap, b, bp = endpoints_of(key)
            yield proto, a, ap, b, bp, key

    # -- derivation --------------------------------------------------------
    def mark_encrypted(self, key: str, evidence: str) -> None:
        flow = self.flows.get(key)
        if flow is None:
            return
        flow.encrypted = True
        if evidence not in flow.encryption_evidence:
            flow.encryption_evidence.append(evidence)

    def mark_cleartext(self, key: str, evidence: str) -> None:
        flow = self.flows.get(key)
        if flow is None:
            return
        if flow.encrypted:
            return
        flow.encrypted = False
        if evidence not in flow.encryption_evidence:
            flow.encryption_evidence.append(evidence)

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    def stats(self) -> Stats:
        """Empty stats: the real numbers are computed by IndexBuilder.compute_stats."""
        return Stats()


class IndexBuilder:
    """Turns raw tshark rows into a :class:`CaptureIndex`."""

    def __init__(self, runner: TsharkRunner) -> None:
        self.runner = runner
        self.index: CaptureIndex | None = None
        self._cert_cache: dict[tuple[str, ...], list[CertFacts]] = {}
        self._sdp_media_ports: list[int] = []

    def build(self) -> CaptureIndex:
        runner = self.runner
        pcap = runner.pcap
        if not pcap.exists():
            raise FileNotFoundError(f"capture not found: {pcap}")
        raw_stats = runner.capture_stats()
        capture = CaptureInfo(
            path=str(pcap.resolve()),
            name=pcap.name,
            sha256=runner.sha,
            size_bytes=pcap.stat().st_size,
            packets=int(raw_stats.get("packets", 0)),
            bytes=int(raw_stats.get("bytes", 0)),
            first_seen=float(raw_stats.get("first", 0.0)),
            last_seen=float(raw_stats.get("last", 0.0)),
            duration=float(raw_stats.get("duration", 0.0)),
            tshark_version=tshark_version(),
        )
        index = CaptureIndex(capture)
        self.index = index

        self._build_flows(index, runner.run("base"))
        self._build_tls(index, runner.run("tls"), runner.run("dtls"))
        self._build_http(index, runner.run("http"))
        self._build_dns(index, runner.run("dns"))
        self._build_sip(index, runner.run("sip"))
        # SIP runs first so SDP can hand us the media ports for decode-as.
        self._build_rtp(index, runner.run("rtp", runner.rtp_decode_args(self._sdp_media_ports)))
        self._build_ssh(index, runner.run("ssh"))
        self._build_quic(index, runner.run("quic"))
        self._build_services(index, runner.run("services"))

        index.dropped_fields = list(runner.dropped_fields)
        index.pass_stats = {k: dict(v) for k, v in runner.stats.items()}
        if index.dropped_fields:
            index.add_note(
                "Some tshark fields were unavailable in this build and were skipped: "
                + ", ".join(index.dropped_fields)
            )
        return index

    # -- flows -------------------------------------------------------------
    def _build_flows(self, index: CaptureIndex, rows: list[Row]) -> None:
        for row in rows:
            src = first(row, "ip.src") or first(row, "ipv6.src")
            dst = first(row, "ip.dst") or first(row, "ipv6.dst")
            sport = to_int(first(row, "tcp.srcport") or first(row, "udp.srcport"))
            dport = to_int(first(row, "tcp.dstport") or first(row, "udp.dstport"))
            if not src or not dst:
                continue
            if "tcp.srcport" in row and row.get("tcp.srcport"):
                proto = "tcp"
            elif row.get("udp.srcport"):
                proto = "udp"
            else:
                proto = "other"
            if sport is None or dport is None:
                continue
            key = flow_key(proto, src, sport, dst, dport)
            flow = index.flows.get(key)
            ts = to_float(first(row, "frame.time_epoch")) or 0.0
            length = to_int(first(row, "frame.len")) or 0
            app = app_proto_from(first(row, "frame.protocols"))
            if flow is None:
                _pa, ea, ppa, eb, ppb = endpoints_of(key)
                frame = to_int(first(row, "frame.number")) or 0
                flow = Flow(
                    key=key,
                    proto="tcp" if proto == "tcp" else "udp",
                    endpoint_a=ea,
                    port_a=ppa,
                    endpoint_b=eb,
                    port_b=ppb,
                    app_proto=app,
                    first_seen=ts,
                    first_frame=frame,
                    last_seen=ts,
                )
                index.flows[key] = flow
                index._flow_by_pair[(ea, ppa)] = key
                index._flow_by_pair[(eb, ppb)] = key
            flow.packets += 1
            flow.bytes += length
            if flow.packets == 1:
                flow.burst_count, flow.last_burst_start = 1, ts
            elif ts - flow.last_seen > BURST_GAP_S:
                gap = ts - flow.last_burst_start
                flow.burst_count += 1
                flow.last_burst_start = ts
                delta = gap - flow.burst_gap_mean
                flow.burst_gap_mean += delta / (flow.burst_count - 1)
                flow.burst_gap_m2 += delta * (gap - flow.burst_gap_mean)
            flow.last_seen = max(flow.last_seen, ts)
            flow.first_seen = min(flow.first_seen, ts) if flow.first_seen else ts
            if app not in {"tcp", "udp", "ethernet", "unknown"}:
                flow.app_proto = app
            if ts and src == flow.endpoint_a and sport == flow.port_a:
                flow.packets_a_to_b += 1
                flow.bytes_a_to_b += length
            stream = to_int(first(row, "tcp.stream") or first(row, "udp.stream"))
            if stream is not None and flow.stream_index is None:
                flow.stream_index = stream
            syn = to_bool01(first(row, "tcp.flags.syn"))
            if syn is not None:
                if syn:
                    flow.syn_count += 1
                if to_bool01(first(row, "tcp.flags.fin")):
                    flow.fin_count += 1
                if to_bool01(first(row, "tcp.flags.reset")):
                    flow.rst_count += 1
            for ip, role_hint in ((src, flow.port_a), (dst, flow.port_b)):
                host = index.hosts.get(ip)
                if host is None:
                    host = Host(ip=ip)
                    index.hosts[ip] = host
                host.first_seen = min(host.first_seen or ts, ts)
                host.last_seen = max(host.last_seen, ts)
                role = "server" if role_hint in {80, 443, 22, 25, 389, 5060, 161, 123, 21, 23} else None
                if role and role not in host.roles:
                    host.roles.append(role)
                _ = role_hint
        for flow in index.flows.values():
            flow.duration = max(0.0, flow.last_seen - flow.first_seen)
            if flow.proto == "tcp":
                flow.handshake_completed = True if flow.syn_count >= 2 else (False if flow.syn_count == 1 else None)
            else:
                flow.handshake_completed = None
            known = {WELL_KNOWN_PORTS.get(flow.port_a), WELL_KNOWN_PORTS.get(flow.port_b)}
            if flow.app_proto in {"tls", "dtls", "quic"}:
                index.mark_encrypted(flow.key, flow.app_proto)
            if flow.app_proto in SENSITIVE_SERVICES and "tls" not in known:
                index.mark_cleartext(flow.key, f"app_proto={flow.app_proto}")
        for host in index.hosts.values():
            for flow in index.flows.values():
                if flow.matches_endpoint(host.ip):
                    host.flows += 1
                    host.bytes += flow.bytes
                    host.packets += flow.packets

    # -- TLS ---------------------------------------------------------------
    def _stream_key(self, index: CaptureIndex, row: Row) -> str | None:
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        sport = to_int(first(row, "tcp.srcport") or first(row, "udp.srcport"))
        dport = to_int(first(row, "tcp.dstport") or first(row, "udp.dstport"))
        if not src or not dst or sport is None or dport is None:
            return None
        proto = "tcp" if row.get("tcp.srcport") else "udp"
        key = flow_key(proto, src, sport, dst, dport)
        if key not in index.flows:
            index.flows[key] = Flow(
                key=key,
                proto="tcp" if proto == "tcp" else "udp",
                endpoint_a=endpoints_of(key)[1],
                port_a=endpoints_of(key)[2],
                endpoint_b=endpoints_of(key)[3],
                port_b=endpoints_of(key)[4],
                app_proto="tls",
            )
        return key

    def _build_tls(self, index: CaptureIndex, tls_rows: list[Row], dtls_rows: list[Row]) -> None:
        """Parse TLS and DTLS rows with one code path (dtls.* is folded to tls.*)."""
        rows = tls_rows + [normalize_dtls_row(row) for row in dtls_rows]
        sessions: dict[str, TlsSession] = {}
        for row in rows:
            key = self._stream_key(index, row)
            if key is None:
                continue
            protocols = first(row, "frame.protocols")
            proto: str = "dtls" if ("dtls" in protocols or proto_from_row(row) == "dtls") else "tls"
            session = sessions.get(key)
            if session is None:
                session = TlsSession(key=key, proto="dtls" if proto == "dtls" else "tls")
                sessions[key] = session
                index.tls[key] = session
                flow = index.flows.get(key)
                if flow is not None:
                    flow.app_proto = session.proto
                    index.mark_encrypted(key, f"{session.proto} handshake")
            frame = to_int(first(row, "frame.number")) or 0
            session.frames.append(frame)
            # One packet can carry several handshake messages (ServerHello +
            # Certificate usually arrive together), and every value matters.
            hts = [to_int(v) for v in row.get("tls.handshake.type", [])]
            record_version = version_name(first(row, "tls.record.version"))
            if record_version and record_version not in session.record_versions:
                session.record_versions.append(record_version)
            src = first(row, "ip.src") or first(row, "ipv6.src")
            if 1 in hts and session.client_hello is None:
                session.client_hello = self._parse_hello(row, 1, frame)
                if first(row, "tls.handshake.ja3"):
                    session.ja3 = first(row, "tls.handshake.ja3")
            if 2 in hts and session.server_hello is None:
                session.server_hello = self._parse_hello(row, 2, frame)
                if first(row, "tls.handshake.ja3s"):
                    session.ja3s = first(row, "tls.handshake.ja3s")
            if 11 in hts:
                session.certs.extend(self._parse_certs(row, frame, self._enrich))
            if 20 in hts:
                session.resumption = True
            elif 21 in hts:
                session.resumption = False
            if first(row, "tls.alert_message.desc"):
                session.alerts.append(
                    TlsAlert(
                        frame=frame,
                        level=to_int(first(row, "tls.alert_message.level")) or 0,
                        description=first(row, "tls.alert_message.desc"),
                    )
                )
            _ = src
        for session in sessions.values():
            self._finalize_tls(index, session)

    def _parse_hello(self, row: Row, htype: int, frame: int) -> Handshake:
        # Every offered suite is its own field occurrence, so all values matter --
        # reading only the first one silently reported "1 suite offered".
        ciphers = [
            cipher
            for chunk in row.get("tls.handshake.ciphersuite", [])
            for cipher in parse_cipher_ids(chunk)
            if cipher not in NON_CIPHER_VALUES
        ]
        ciphers = list(dict.fromkeys(ciphers))
        return Handshake(
            type=htype,
            frame=frame,
            legacy_version=version_name(first(row, "tls.handshake.version")),
            supported_versions=normalize_version_list(many(row, "tls.handshake.extensions.supported_version")),
            cipher_suites=ciphers if htype == 1 else [],
            cipher_suite=ciphers[0] if (htype == 2 and ciphers) else None,
            compression_methods=to_int_list(many(row, "tls.handshake.compression_methods")),
            sni=first(row, "tls.handshake.extensions_server_name") or None,
            alpn=many(row, "tls.handshake.extensions_alpn_str"),
            supported_groups=many(row, "tls.handshake.extensions_supported_group"),
            sig_algs=many(row, "tls.handshake.extensions_signature_algorithms"),
            session_id=first(row, "tls.handshake.session_id_length") or None,
        )

    def _enrich(self, hex_values: list[str]) -> list[CertFacts]:
        """Resolve real certificate facts through openssl, once per message."""
        if not hex_values:
            return []
        cached = self._cert_cache.get(tuple(hex_values))
        if cached is not None:
            return cached
        facts, notes = enrich_all(hex_values)
        for note in notes:
            self.index.add_note(f"[certs] {note}") if self.index else None
        self._cert_cache[tuple(hex_values)] = facts
        return facts

    def _parse_certs(
        self,
        row: Row,
        frame: int,
        enrich: Callable[[list[str]], list[CertFacts]] | None = None,
    ) -> list[Cert]:
        times = many(row, "x509af.utcTime") or many(row, "x509af.generalizedTime")
        names = many(row, "x509sat.uTF8String")
        printable = many(row, "x509sat.printableString")
        countries = many(row, "x509sat.CountryName")
        emails = many(row, "x509sat.IA5String")
        sans = many(row, "x509ce.dNSName")
        modulus = first(row, "x509ce.modulus")
        spki = first(row, "x509af.subjectPublicKey")
        sig_oid = first(row, "x509af.algorithmId") or None
        count = max(1, len(times) // 2) if times else 1
        per = max(1, len(names) // count) if names else 0
        certs: list[Cert] = []
        for i in range(count):
            slice_names = names[i * per : (i + 1) * per] if per else []
            cn = slice_names[-1] if slice_names else (sans[0] if sans else None)
            certs.append(
                Cert(
                    chain_index=i,
                    common_names=[cn] if cn else [],
                    organizations=slice_names[:-1] if len(slice_names) > 1 else [],
                    emails=emails[i : i + 1],
                    countries=countries[i : i + 1],
                    not_before=times[i * 2] if len(times) > i * 2 else None,
                    not_after=times[i * 2 + 1] if len(times) > i * 2 + 1 else None,
                    public_key_bits=_credible_bits(public_key_bits(modulus, spki)),
                    signature_algorithm_oid=sig_oid,
                    san_dns=sans,
                    self_signed_suspected=count == 1 and bool(slice_names),
                    name_source="tshark-rdn-flattened",
                    frame=frame,
                )
            )
        if printable and certs:
            certs[0].organizations = printable[: len(printable)] or certs[0].organizations
        if enrich is not None:
            apply_openssl_facts(certs, enrich(row.get("tls.handshake.certificate", [])))
        return certs

    def _finalize_tls(self, index: CaptureIndex, session: TlsSession) -> None:
        ch, sh = session.client_hello, session.server_hello
        if ch:
            session.sni = ch.sni or session.sni
            session.offered_ciphers = list(dict.fromkeys(ch.cipher_suites))
            session.groups = list(dict.fromkeys(ch.supported_groups))
            if ch.alpn:
                session.alpn = ch.alpn
        if sh:
            session.chosen_cipher = sh.cipher_suite
            if sh.alpn:
                session.alpn = sh.alpn
            if sh.sni:
                session.sni = sh.sni
        versions: list[str] = []
        for source in (ch.supported_versions if ch else [], sh.supported_versions if sh else []):
            for v in source:
                if v not in versions:
                    versions.append(v)
        session.negotiated_version = (
            versions[0] if versions else (sh.legacy_version if sh else (ch.legacy_version if ch else None))
        )
        if session.offered_ciphers:
            counts = {c: 0 for c in session.offered_ciphers}
            _ = counts
        session.complete = bool(ch and sh and session.chosen_cipher is not None)
        session.truncated = bool(ch and not sh)
        from .data_ciphers import forward_secrecy_for

        fs, reason = forward_secrecy_for(session)
        session.forward_secrecy = fs
        session.forward_secrecy_reason = reason

    # -- HTTP --------------------------------------------------------------
    def _build_http(self, index: CaptureIndex, rows: list[Row]) -> None:
        by_stream: dict[tuple[str, str], HttpExchange] = {}
        for row in rows:
            key = self._stream_key(index, row) or ""
            if not key:
                continue
            stream = first(row, "tcp.stream") or key
            exch = by_stream.get((key, stream))
            frame = to_int(first(row, "frame.number")) or 0
            method = first(row, "http.request.method")
            status = to_int(first(row, "http.response.code"))
            if exch is None:
                flow = index.flows.get(key)
                # TLS runs before HTTP, so a flow already marked encrypted here
                # really is HTTP carried inside TLS. Plain HTTP stays cleartext.
                exch = HttpExchange(
                    key=key,
                    frame=frame,
                    is_encrypted=bool(flow and flow.encrypted),
                )
                by_stream[(key, stream)] = exch
                index.http.append(exch)
            if method:
                exch.method = method
                exch.host = first(row, "http.host") or exch.host
                exch.uri = first(row, "http.request.uri") or exch.uri
                exch.version = first(row, "http.request.version") or exch.version
                exch.user_agent = first(row, "http.user_agent") or exch.user_agent
            if status:
                exch.status = status
            auth = first(row, "http.authorization")
            if auth:
                scheme = auth.split(None, 1)[0] if " " in auth else "unknown"
                exch.auth_present = True
                exch.auth_scheme = scheme
                exch.auth_value_preview = redact_auth(auth)
            for cookie in many(row, "http.set_cookie"):
                name = cookie.split("=", 1)[0]
                if name not in exch.cookies_set:
                    exch.cookies_set.append(name)
                lowered = cookie.lower()
                if "secure" not in lowered and name not in exch.cookie_flags_insecure:
                    exch.cookie_flags_insecure.append(name)
            if first(row, "http.cookie"):
                exch.body_frames.append(frame)
        for exch in index.http:
            if not exch.is_encrypted:
                index.mark_cleartext(exch.key, f"http {exch.method or 'traffic'}")

    # -- DNS ---------------------------------------------------------------
    def _build_dns(self, index: CaptureIndex, rows: list[Row]) -> None:
        pending: dict[tuple[str, int], list[DnsQuery]] = defaultdict(list)
        for row in rows:
            key = self._stream_key(index, row)
            if not key:
                continue
            frame = to_int(first(row, "frame.number")) or 0
            names = many(row, "dns.qry.name")
            qtypes = many(row, "dns.qry.type")
            is_response = to_bool01(first(row, "dns.flags.response"))
            flow = index.flows.get(key)
            over_tls = bool(flow and flow.app_proto in {"tls", "dtls"})
            if names:
                query = DnsQuery(
                    key=key,
                    frame=frame,
                    name=names[0],
                    qtype=qtypes[0] if qtypes else "?",
                    over_tls=over_tls,
                    is_response=is_response is True,
                )
                index.dns.append(query)
                if not is_response:
                    pending[(key, frame)].append(query)
            else:
                answers = many(row, "dns.a") + many(row, "dns.aaaa") + many(row, "dns.cname")
                rcode = first(row, "dns.flags.rcode")
                for bucket in pending.values():
                    for query in bucket:
                        if query.response_frame is None and abs(query.frame - frame) < 200:
                            query.response_frame = frame
                            query.answers = answers
                            query.rcode = rcode or None
            _ = (names, qtypes, is_response)

    # -- SIP / SDP ---------------------------------------------------------
    def _build_sip(self, index: CaptureIndex, rows: list[Row]) -> None:
        for row in rows:
            key = self._stream_key(index, row)
            if not key:
                continue
            frame = to_int(first(row, "frame.number")) or 0
            method = first(row, "sip.Method")
            status = to_int(first(row, "sip.Status-Code"))
            sdp_lines = many(row, "sdp.crypto.crypto_suite") or many(row, "sdp.crypto")
            media = many(row, "sdp.media")
            sdp_ports = many(row, "sdp.media.port")
            if not method and not status and not sdp_lines and not media:
                continue
            msg = SipMessage(
                key=key,
                frame=frame,
                kind="response" if status else "request",
                method=method or None,
                status=status,
                reason=_status_reason(first(row, "sip.Status-Line")),
                call_id=first(row, "sip.Call-ID") or None,
                cseq=first(row, "sip.CSeq") or None,
                from_user=first(row, "sip.from.user") or None,
                to_user=first(row, "sip.to.user") or None,
                user_agent=first(row, "sip.User-Agent") or None,
                transport=_via_transport(first(row, "sip.Via")),
                has_auth_header=bool(first(row, "sip.auth") or first(row, "sip.auth.algorithm")),
                auth_scheme=first(row, "sip.auth.algorithm") or None,
                sdp_crypto_lines=sdp_lines,
                sdp_media=media,
                sdp_protected=bool(sdp_lines),
                port_hint=to_int(first(row, "udp.srcport")) or to_int(first(row, "tcp.srcport")),
            )
            flow = index.flows.get(key)
            msg.via_encrypted_transport = bool(flow and flow.encrypted)
            index.sip.append(msg)
            for port in self._media_ports(media) or [to_int(p_) or 0 for p_ in sdp_ports]:
                if port not in self._sdp_media_ports:
                    self._sdp_media_ports.append(port)
            if not msg.via_encrypted_transport:
                index.mark_cleartext(key, f"sip {msg.method or msg.status}")

    # -- RTP ---------------------------------------------------------------
    @staticmethod
    def _media_ports(media_lines: list[str]) -> list[int]:
        """Ports from SDP ``m=audio <port> RTP/AVP ...`` lines."""
        ports: list[int] = []
        for line in media_lines:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].startswith("m=") and parts[2:3] and parts[2].startswith("RTP"):
                port = to_int(parts[1])
                if port:
                    ports.append(port)
        return ports

    def _build_rtp(self, index: CaptureIndex, rows: list[Row]) -> None:
        streams: dict[tuple[str, int | None], RtpStream] = {}
        for row in rows:
            key = self._stream_key(index, row)
            if not key:
                continue
            src = first(row, "ip.src") or first(row, "ipv6.src")
            dst = first(row, "ip.dst") or first(row, "ipv6.dst")
            ssrc = to_int_auto(first(row, "rtp.ssrc"))
            bucket = streams.setdefault(
                (key, ssrc),
                RtpStream(
                    key=key,
                    ssrc=ssrc,
                    from_ip=src,
                    to_ip=dst,
                    payload_type=to_int_auto(first(row, "rtp.p_type")),
                    payload_name=RTP_PAYLOAD_TYPES.get(to_int_auto(first(row, "rtp.p_type")) or -1),
                    first_frame=to_int(first(row, "frame.number")) or 0,
                ),
            )
            ts = to_float(first(row, "frame.time_epoch")) or 0.0
            length = to_int(first(row, "frame.len")) or 0
            bucket.packets += 1
            bucket.bytes += length
            if bucket.first_seen == 0.0:
                bucket.first_seen = ts
            bucket.last_seen = max(bucket.last_seen, ts)
        index.rtp.extend(streams.values())
        for stream in index.rtp:
            index.mark_cleartext(stream.key, f"rtp ssrc={stream.ssrc} pt={stream.payload_type}")

    # -- SSH ---------------------------------------------------------------
    def _build_ssh(self, index: CaptureIndex, rows: list[Row]) -> None:
        by_stream: dict[str, SshSession] = {}
        for row in rows:
            key = self._stream_key(index, row)
            if not key:
                continue
            stream = first(row, "tcp.stream") or key
            sess = by_stream.get(stream)
            frame = to_int(first(row, "frame.number")) or 0
            if sess is None:
                sess = SshSession(key=key, frame=frame)
                by_stream[stream] = sess
                index.ssh.append(sess)
                index.mark_encrypted(key, "ssh kex")
            version = first(row, "ssh.protocol")
            if version and not sess.client_version:
                sess.client_version = version
            elif version:
                sess.server_version = version
            for attr, field in (
                ("kex_algorithms", "ssh.kex_algorithms"),
                ("host_key_algorithms", "ssh.server_host_key_algorithms"),
                ("ciphers", "ssh.encryption_algorithms_client_to_server"),
                ("macs", "ssh.mac_algorithms_client_to_server"),
                ("compression", "ssh.compression_algorithms_client_to_server"),
            ):
                values = many(row, field)
                if not values:
                    continue
                current = getattr(sess, attr)
                for value in values:
                    if value not in current:
                        current.append(value)
                    if frame not in sess.offered_in.setdefault(value, []):
                        sess.offered_in[value].append(frame)

    # -- QUIC --------------------------------------------------------------
    def _build_quic(self, index: CaptureIndex, rows: list[Row]) -> None:
        seen: set[str] = set()
        for row in rows:
            key = self._stream_key(index, row)
            if not key or key in seen:
                continue
            seen.add(key)
            frame = to_int(first(row, "frame.number")) or 0
            versions = normalize_version_list(many(row, "quic.version") + many(row, "quic.supported_version"))
            sni = first(row, "tls.handshake.extensions_server_name") or None
            if not versions and not sni:
                continue
            index.quic.append(
                QuicSession(
                    key=key,
                    frame=frame,
                    versions=versions,
                    sni=sni,
                    cipher_suites=parse_cipher_ids(first(row, "tls.handshake.ciphersuite")),
                    tls_versions=normalize_version_list(many(row, "tls.handshake.extensions.supported_version")),
                    alpn=many(row, "tls.handshake.extensions_alpn_str"),
                )
            )
            index.mark_encrypted(key, "quic")

    # -- other services ----------------------------------------------------
    def _build_services(self, index: CaptureIndex, rows: list[Row]) -> None:
        for row in rows:
            key = self._stream_key(index, row)
            if not key:
                continue
            frame = to_int(first(row, "frame.number")) or 0
            protocols = {
                field: first(row, field)
                for field in SERVICE_FIELDS
                if first(row, field)
            }
            if not protocols:
                continue
            protocol = next(iter(protocols))
            detail = " | ".join(
                f"{k}=<redacted {len(v)} chars>"
                if k in REDACTED_SERVICE_FIELDS
                or (k == "ftp.request.arg" and (protocols.get("ftp.request.command") or "").upper() == "PASS")
                else f"{k}={v}"
                for k, v in protocols.items()
            )
            flow = index.flows.get(key)
            app = flow.app_proto if flow else protocol
            hit = ServiceHit(
                key=key,
                frame=frame,
                protocol=app,
                detail=detail[:400],
                sensitive=bool(SENSITIVE_SERVICES.get(app, False)),
            )
            index.services.append(hit)
            if hit.sensitive and not (flow and flow.encrypted):
                index.mark_cleartext(key, f"{app} plaintext")

    # -- stats -------------------------------------------------------------
    def compute_stats(self, findings: list[Finding]) -> Stats:
        index = self.index
        assert index is not None
        sev: Counter[str] = Counter(f.severity for f in findings)
        det: Counter[str] = Counter(f.detector for f in findings)
        apps: Counter[str] = Counter(f.app_proto for f in index.flows.values())
        enc = sum(1 for f in index.flows.values() if f.encrypted is True)
        clear = sum(1 for f in index.flows.values() if f.encrypted is False)
        unknown = sum(1 for f in index.flows.values() if f.encrypted is None)
        return Stats(
            packets=index.capture.packets,
            bytes=index.capture.bytes,
            flows=len(index.flows),
            encrypted_flows=enc,
            cleartext_flows=clear,
            unknown_flows=unknown,
            hosts=len(index.hosts),
            tls_sessions=len(index.tls),
            quic_sessions=len(index.quic),
            sip_messages=len(index.sip),
            rtp_streams=len(index.rtp),
            dns_queries=len(index.dns),
            http_exchanges=len(index.http),
            ssh_sessions=len(index.ssh),
            findings_by_severity=dict(sorted(sev.items())),
            findings_by_detector=dict(sorted(det.items())),
            app_protocols=dict(apps.most_common()),
        )


#: Service-detail fields that carry credentials in cleartext and must never
#: reach a report verbatim. Values are replaced with a length-only placeholder.
REDACTED_SERVICE_FIELDS: frozenset[str] = frozenset({"snmp.community", "mysql.query", "ldap.simple"})


def redact_auth(value: str) -> str:
    """Keep the scheme, hide the credential. Never log secrets verbatim."""
    if " " not in value:
        return f"<redacted {len(value)} chars>"
    scheme, rest = value.split(None, 1)
    if scheme.lower() == "basic":
        return f"{scheme} <redacted {len(rest)} chars>"
    if scheme.lower() == "digest":
        fields = [p for p in rest.split(",") if not p.strip().lower().startswith(("response=", "nonce="))]
        return f"{scheme} <redacted; {' '.join(fields).strip()[:80]}>"
    return f"{scheme} <redacted {len(rest)} chars>"


def first_of(session: TlsSession, attr: str) -> str | None:  # pragma: no cover - helper
    return getattr(session, attr, None)


def utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def role_of(port: int) -> Role:
    return Role.CLIENT if port < 1024 or port in {5060, 8080} else Role.SERVER


def build_index(pcap: Path, **kwargs: Any) -> CaptureIndex:
    """Convenience wrapper: one capture in, one index out."""
    return IndexBuilder(TsharkRunner(pcap, **kwargs)).build()


def _credible_bits(bits: int | None) -> int | None:
    """Drop key sizes too small to be a real certificate public key."""
    if bits is None or bits < 128:
        return None
    return bits


RTP_PAYLOAD_TYPES: dict[int, str] = {
    0: "PCMU", 3: "GSM", 4: "G723", 8: "PCMA", 9: "G722", 10: "L16-44100",
    14: "MPA", 15: "G728", 18: "G729", 31: "H261", 33: "MPV2", 34: "MP2T",
    96: "dynamic", 97: "dynamic", 98: "dynamic", 99: "dynamic",
}


def normalize_dtls_row(row: Row) -> Row:
    """Fold ``dtls.*`` field names onto ``tls.*`` so one parser handles both."""
    out: Row = {}
    for key, values in row.items():
        out["tls." + key[5:] if key.startswith("dtls.") else key] = values
    if "dtls" not in out.get("frame.protocols", [""])[0] and "frame.protocols" in row:
        out["frame.protocols"] = ["dtls:" + out["frame.protocols"][0]]
    return out


def proto_from_row(row: Row) -> str:
    return "dtls" if "dtls" in first(row, "frame.protocols") else "tls"


def _status_reason(status_line: str) -> str | None:
    parts = status_line.split(None, 2)
    return parts[2].strip() if len(parts) == 3 else (status_line.strip() or None)


def _via_transport(via: str) -> str | None:
    match = re.search(r"SIP/2\.0/(TCP|UDP|TLS|SCTP)", via, re.IGNORECASE)
    return match.group(1).upper() if match else (via.strip()[:20] or None)
