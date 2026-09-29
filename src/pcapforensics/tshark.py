"""Thin, deterministic wrapper around the ``tshark`` binary.

Why subprocess ``tshark -T fields`` and not pyshark:

* field names stay visible and version-pinned (``docs/tshark-fields.md``),
* py3.13+ support is not a coin flip,
* one process per pass is far faster than per-packet IPC,
* output is text we can snapshot in tests.

Every pass result is cached on disk keyed by (pcap sha256, tshark version,
pass name) so re-runs and test loops are cheap.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

TAB = "\t"
AGG = "\x1f"  # unit separator: safe inside field values, never in tshark output
MULTI = "\x1e"  # record separator, used by -z statistics passes

Row = dict[str, list[str]]


class TsharkMissingError(RuntimeError):
    pass


class TsharkRunError(RuntimeError):
    pass


@dataclass(frozen=True)
class PassSpec:
    """One tshark invocation profile."""

    name: str
    fields: tuple[str, ...]
    display_filter: str | None = None
    columns: str | None = None  # for -z passes


#: Every protocol pass needs addresses; IPv4 and IPv6 both, because a capture
#: with only one family otherwise silently yields zero flows.
ADDR_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
)


def with_addr(fields: tuple[str, ...]) -> tuple[str, ...]:
    rest = tuple(f for f in fields if f not in ADDR_FIELDS)
    return ADDR_FIELDS + rest


BASE_PASS = PassSpec(
    name="base",
    fields=(
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.flags.syn",
        "tcp.flags.fin",
        "tcp.flags.reset",
        "tcp.flags.push",
        "tcp.analysis.ack_rtt",
        "udp.srcport",
        "udp.dstport",
        "udp.stream",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "icmp.type",
        "icmp.code",
        "_ws.col.Protocol",
    ),
)

TLS_PASS = PassSpec(
    name="tls",
    display_filter="tls.handshake || tls.alert_message",
    fields=with_addr((
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.stream",
        "udp.stream",
        "tls.record.version",
        "tls.handshake.type",
        "tls.handshake.version",
        "tls.handshake.ciphersuite",
        "tls.handshake.ciphersuites",
        "tls.handshake.compression_method",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.extensions_supported_group",
        "tls.handshake.extensions_signature_algorithm",
        "tls.handshake.extensions_session_ticket",
        "tls.handshake.session_id_length",
        "tls.handshake.downgrade_sentinel",
        "tls.handshake.ja3",
        "tls.handshake.ja3s",
        "tls.handshake.certificate",
        "tls.alert_message.level",
        "tls.alert_message.desc",
        "x509af.utcTime",
        "x509af.generalizedTime",
        "x509af.algorithmId",
        "x509ce.dNSName",
        "x509ce.modulus",
        "x509af.subjectPublicKey",
        "x509sat.uTF8String",
        "x509sat.printableString",
        "x509sat.IA5String",
        "x509sat.CountryName",
    )),
)

TLS_ALERT_PASS = PassSpec(
    name="tls_alert",
    display_filter="tls.alert_message",
    fields=with_addr((
        "tcp.stream",
        "tls.alert_message.level",
        "tls.alert_message.desc",
    )),
)

HTTP_PASS = PassSpec(
    name="http",
    display_filter="http.request || http.response",
    fields=with_addr((
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.request.version",
        "http.response.code",
        "http.user_agent",
        "http.authorization",
        "http.cookie",
        "http.set_cookie",
    )),
)

DNS_PASS = PassSpec(
    name="dns",
    display_filter="dns",
    fields=with_addr((
        "udp.srcport",
        "udp.dstport",
        "tcp.srcport",
        "tcp.dstport",
        "udp.stream",
        "dns.flags.response",
        "dns.id",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.rcode",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
        "dns.resp.name",
        "dns.txt",
        "dns.count.answers",
    )),
)

SIP_PASS = PassSpec(
    name="sip",
    display_filter="sip || sdp",
    fields=with_addr((
        "udp.srcport",
        "udp.dstport",
        "tcp.stream",
        "sip.Method",
        "sip.Status-Code",
        "sip.Status-Line",
        "sip.Call-ID",
        "sip.CSeq",
        "sip.from.user",
        "sip.to.user",
        "sip.User-Agent",
        "sip.Via",
        "sip.auth",
        "sip.auth.algorithm",
        "sdp.media",
        "sdp.media.proto",
        "sdp.media.port",
        "sdp.connection.address",
        "sdp.crypto",
        "sdp.crypto.crypto_suite",
        "sdp.crypto.key_method",
    )),
)

RTP_PASS = PassSpec(
    name="rtp",
    display_filter="rtp",
    fields=with_addr((
        "frame.time_epoch",
        "frame.len",
        "udp.srcport",
        "udp.dstport",
        "rtp.ssrc",
        "rtp.p_type",
        "rtp.seq",
        "rtp.timestamp",
    )),
)

SSH_PASS = PassSpec(
    name="ssh",
    display_filter="ssh",
    fields=with_addr((
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "ssh.protocol",
        "ssh.message_code",
        
        "ssh.kex_algorithms",
        "ssh.server_host_key_algorithms",
        "ssh.encryption_algorithms_client_to_server",
        "ssh.mac_algorithms_client_to_server",
        "ssh.compression_algorithms_client_to_server",
    )),
)

QUIC_PASS = PassSpec(
    name="quic",
    display_filter="quic",
    fields=with_addr((
        "udp.srcport",
        "udp.dstport",
        "quic.version",
        "quic.supported_version",
        "quic.long.packet_type",
        "tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "tls.handshake.ciphersuites",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.extensions_alpn_str",
    )),
)

SERVICE_PASS = PassSpec(
    name="services",
    display_filter="ntp || tftp || ftp || ftp-data || telnet || snmp || ldap || smtp || imap || pop || resp || mysql",
    fields=with_addr((
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "ntp.refid",
        "tftp.source_file",
        "tftp.destination_file",
        "ftp.request.command",
        "ftp.request.arg",
        "snmp.version",
        "snmp.community",
        "snmp.var-bind_str",
        "ldap.protocolOp",
        "ldap.name",
        "ldap.version",
        "smtp.req.command",
        "pop.request.command",
        "mysql.command",
        "mysql.query",
        "mysql.user",
    )),
)

#: DTLS carries the same handshake fields under a ``dtls.`` prefix. The index
#: normalises the prefix away, so one parser serves both.
DTLS_PASS = PassSpec(
    name="dtls",
    display_filter="dtls.handshake || dtls.alert_message",
    fields=with_addr(
        tuple("dtls." + f[4:] if f.startswith("tls.") else f for f in TLS_PASS.fields)
    ),
)

IPV6_ADDR_PASS = PassSpec(
    name="ipv6",
    display_filter="ipv6",
    fields=("frame.number", "ipv6.src", "ipv6.dst", "ipv6.hop_limit", "ipv6.plen"),
)

PASSES: dict[str, PassSpec] = {
    p.name: p
    for p in (
        BASE_PASS,
        TLS_PASS,
        DTLS_PASS,
        HTTP_PASS,
        DNS_PASS,
        SIP_PASS,
        RTP_PASS,
        SSH_PASS,
        QUIC_PASS,
        SERVICE_PASS,
        IPV6_ADDR_PASS,
    )
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@lru_cache(maxsize=1)
def tshark_path() -> str:
    found = shutil.which("tshark")
    if not found:
        raise TsharkMissingError(
            "tshark not found on PATH. Install Wireshark/tshark (macOS: brew install wireshark)."
        )
    return found


@lru_cache(maxsize=1)
def tshark_version() -> str:
    """Short version string, e.g. ``4.6.6 (Git commit ...)``."""
    out = subprocess.run([tshark_path(), "-v"], capture_output=True, text=True, check=False).stdout
    first = out.splitlines()[0] if out else "unknown"
    return first.replace("TShark (Wireshark)", "").strip()


@lru_cache(maxsize=1)
def valid_fields() -> frozenset[str]:
    """Every field name this tshark build exposes (``-G fields``, 3rd column)."""
    out = subprocess.run([tshark_path(), "-G", "fields"], capture_output=True, text=True, check=False).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            name = parts[2].strip()
            if name:
                names.add(name)
    return frozenset(names)


@lru_cache(maxsize=1)
def protocol_names() -> frozenset[str]:
    """Short protocol names usable in a display filter (``-G protocols``)."""
    out = subprocess.run([tshark_path(), "-G", "protocols"], capture_output=True, text=True, check=False).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip():
            names.add(parts[2].strip())
    return frozenset(names)


@lru_cache(maxsize=1)
def default_prefs() -> frozenset[str]:
    """Preference names this tshark build knows about (``-G defaultprefs``).

    Every entry in that dump is commented out with ``#``, so the marker is
    stripped before the name is collected.
    """
    out = subprocess.run(
        [tshark_path(), "-G", "defaultprefs"], capture_output=True, text=True, check=False
    ).stdout
    names: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        line = line.lstrip("#").strip()
        if not line:
            continue
        name = line.split(None, 1)[0].rstrip(":")
        if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            names.add(name)
    return frozenset(names)


WANTED_PREFS: tuple[str, ...] = (
    "tcp.desegment_tcp_streams",
    "tcp.desegment_tcp_streams_lua",
    "tls.desegment_ssl_records",
    "tls.desegment_ssl_application_data",
    "dtls.desegment_dtls_records",
    "dtls.desegment_app_data",
    "ip.defragment",
    "ipv6.defragment",
)

#: Preferences rejected by the running tshark, discovered at runtime.
_UNSUPPORTED_PREFS: set[str] = set()


def _supported_prefs() -> tuple[str, ...]:
    known = default_prefs()
    prefs = WANTED_PREFS if not known else tuple(p for p in WANTED_PREFS if p in known)
    return tuple(p for p in prefs if p not in _UNSUPPORTED_PREFS)


@lru_cache(maxsize=1)
def capture_interface_types() -> list[str]:
    """Physical interface types present in this tshark build (e.g. EN10MB)."""
    out = subprocess.run([tshark_path(), "-G", "values"], capture_output=True, text=True, check=False)
    return out.stdout.splitlines()


def file_sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def cache_dir() -> Path:
    env = os.environ.get("PCAP_FORENSICS_CACHE")
    base = Path(env) if env else Path.home() / ".cache" / "pcap-forensics"
    base.mkdir(parents=True, exist_ok=True)
    return base


def split_multi(value: str) -> list[str]:
    return [chunk for chunk in value.split(AGG) if chunk != ""]


def to_int(value: str, base: int = 10) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value, base)
    except ValueError:
        return None


def to_int_list(values: list[str], base: int = 10) -> list[int]:
    out: list[int] = []
    for v in values:
        for part in v.split(","):
            parsed = to_int(part.strip(), base)
            if parsed is not None:
                out.append(parsed)
    return out


def to_int_auto(value: str) -> int | None:
    """Parse an integer that tshark may print in hex (``0xd2bd4e3e``) or decimal."""
    value = value.strip()
    if not value:
        return None
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def to_float(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def to_bool01(value: str) -> bool | None:
    """tshark renders boolean fields as 1/0 *and* as True/False depending on build."""
    value = value.strip().lower()
    if value in {"1", "true", "set"}:
        return True
    if value in {"0", "false", "unset"}:
        return False
    return None


def parse_cipher_ids(value: str) -> list[int]:
    """Parse a tshark cipher list (``0x1301,0x1302``) into ints.

    Only ``0x``-prefixed tokens are hex. tshark always emits the prefix, and
    guessing that a bare ``4865`` is hex silently turns 0x1301 into 0x4865.
    """
    out: list[int] = []
    for part in re.split(r"[,\s]+", value.strip()):
        part = part.strip()
        if not part:
            continue
        try:
            if part.lower().startswith("0x"):
                out.append(int(part, 16))
            else:
                out.append(int(part))
        except ValueError:
            try:
                out.append(int(part, 16))
            except ValueError:
                continue
    return out


def parse_hex_bits(value: str) -> int | None:
    """RSA public-key modulus (hex) -> bit length.

    Measured in bytes, not stripped nibbles: a modulus with a leading zero
    nibble is still the advertised key size, and a real modulus is never all
    zeros.
    """
    value = value.strip().replace(":", "")
    if not value or not _HEX_RE.match(value):
        return None
    if len(value) % 2 == 1 and value[0] == "0":
        value = value[1:]
    if not value:
        return None
    return max(1, (len(value) // 2) * 8)


#: DER encodings of the named-curve OIDs, mapped to the curve's field size.
#: Used when tshark gives us the SubjectPublicKeyInfo blob but no modulus
#: (EC keys have no modulus, so key size has to come from the curve).
EC_CURVE_OIDS: dict[str, int] = {
    "2a8648ce3d030105": 192,  # 1.2.840.10045.3.1.1  prime192v1
    "2a8648ce3d030107": 256,  # 1.2.840.10045.3.1.7  prime256v1 / secp256r1
    "2b81040022": 224,  # 1.3.132.0.33  secp224r1
    "2b81040023": 384,  # 1.3.132.0.34  secp384r1
    "2b81040024": 521,  # 1.3.132.0.35  secp521r1
}


def public_key_bits(modulus_hex: str = "", spki_hex: str = "") -> int | None:
    """Best-effort public-key size: RSA modulus first, then the EC curve OID."""
    if modulus_hex:
        bits = parse_hex_bits(modulus_hex)
        if bits:
            return bits
    blob = (spki_hex or "").strip().replace(":", "").lower()
    if blob and _HEX_RE.match(blob):
        for oid, bits in EC_CURVE_OIDS.items():
            if oid in blob:
                return bits
    return None


class TsharkRunner:
    """Executes passes over one capture, with a content-addressed disk cache."""

    def __init__(
        self,
        pcap: Path,
        *,
        use_cache: bool = True,
        timeout: int = 600,
        extra_args: tuple[str, ...] = (),
    ) -> None:
        self.pcap = pcap
        self.timeout = timeout
        self.use_cache = use_cache
        self.extra_args = extra_args
        self.version = tshark_version()
        self.sha = file_sha256(pcap) if pcap.is_file() else "unknown"
        self.stats: dict[str, dict[str, int | float | str]] = {}
        self.dropped_fields: list[str] = []
        self._field_blacklist: set[str] = set()
        self._banned_protocols: set[str] = set()

    # -- internals ---------------------------------------------------------
    def usable_fields(self, spec: PassSpec) -> tuple[str, ...]:
        """Drop fields this tshark build does not know, recording the drift."""
        known = valid_fields()
        if not known:
            return spec.fields
        keep: list[str] = []
        for field in spec.fields:
            if field in self._field_blacklist:
                dropped = f"{spec.name}:{field}"
                if dropped not in self.dropped_fields:
                    self.dropped_fields.append(dropped)
                continue
            # _ws.col.* display columns are not listed by `-G fields` but are valid.
            if field in known or field.startswith("_ws."):
                keep.append(field)
                continue
            dropped = f"{spec.name}:{field}"
            if dropped not in self.dropped_fields:
                self.dropped_fields.append(dropped)
        return tuple(keep)

    def _cache_file(self, pass_name: str, extra_args: tuple[str, ...] = ()) -> Path:
        suffix = ""
        if extra_args:
            suffix = "-" + hashlib.sha256("\x1f".join(extra_args).encode()).hexdigest()[:8]
        return cache_dir() / self.sha[:16] / f"{self.version.split()[0]}-{pass_name}{suffix}.json"

    def _filter_for(self, spec: PassSpec) -> str | None:
        """Drop protocol tokens this tshark build does not know, recording the drift."""
        if not spec.display_filter:
            return None
        if not protocol_names():
            return spec.display_filter
        kept: list[str] = []
        known = protocol_names()
        for token in spec.display_filter.split("||"):
            token = token.strip()
            if not token:
                continue
            if token in self._banned_protocols:
                continue
            if " " in token or any(op in token for op in "()=<>!"):
                kept.append(token)  # expression, not a bare protocol name: keep as written
                continue
            if token in known or token.split(".")[0] in known:
                kept.append(token)
                continue
            dropped = f"{spec.name}:filter!{token}"
            if dropped not in self.dropped_fields:
                self.dropped_fields.append(dropped)
        return " || ".join(kept) if kept else None

    def _command(self, spec: PassSpec, extra_args: tuple[str, ...] = ()) -> list[str]:
        cmd = [tshark_path(), "-r", str(self.pcap), "-n", "-l"]
        display_filter = self._filter_for(spec)
        if display_filter:
            cmd += ["-Y", display_filter]
        if spec.fields:
            fields = self.usable_fields(spec)
            cmd += [
                "-T",
                "fields",
                "-E",
                f"separator={TAB}",
                "-E",
                "occurrence=a",
                "-E",
                f"aggregator={AGG}",
                "-E",
                "header=y",
                "-E",
                "quote=n",
            ]
            for field in fields:
                cmd += ["-e", field]
        for pref in _supported_prefs():
            cmd += ["-o", f"{pref}:TRUE"]
        cmd += list(self.extra_args) + list(extra_args)
        return cmd

    def _run(self, spec: PassSpec, extra_args: tuple[str, ...] = ()) -> list[Row]:
        fields = self.usable_fields(spec)
        cache = self._cache_file(spec.name, extra_args)
        if self.use_cache and cache.exists():
            try:
                payload = json.loads(cache.read_text())
                if (
                    payload.get("sha") == self.sha
                    and payload.get("fields") == list(fields)
                    and payload.get("extra") == list(extra_args)
                ):
                    self.stats[spec.name] = {"rows": len(payload["rows"]), "cached": 1}
                    return [Row(r) for r in payload["rows"]]
            except (json.JSONDecodeError, KeyError, TypeError):
                cache.unlink(missing_ok=True)

        cmd = self._command(spec, extra_args)
        for _attempt in range(6):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=self.timeout)
            if proc.returncode == 0:
                break
            bad_pref = re.search(r'-o flag "([^"]+)" specifies unknown preference', proc.stderr)
            if bad_pref:
                offending = bad_pref.group(1).split(":", 1)[0]
                if offending not in _UNSUPPORTED_PREFS:
                    _UNSUPPORTED_PREFS.add(offending)
                    cmd = self._command(spec, extra_args)
                    continue
            bad_proto = re.search(r'"([A-Za-z0-9_.-]+)" is not a valid protocol or protocol field', proc.stderr)
            if bad_proto:
                offender = bad_proto.group(1)
                self._banned_protocols.add(offender)
                cmd = self._command(spec, extra_args)
                continue
            bad_field = re.search(r"^\t(\S+) is not a valid field", proc.stderr, re.MULTILINE)
            if bad_field:
                field = bad_field.group(1)
                dropped = f"{spec.name}:{field}"
                if dropped not in self.dropped_fields:
                    self.dropped_fields.append(dropped)
                self._field_blacklist.add(field)
                cmd = self._command(spec, extra_args)
                continue
            raise TsharkRunError(
                f"tshark pass {spec.name!r} failed (exit {proc.returncode}):\n"
                f"{proc.stderr.strip()[:2000]}\ncmd: {' '.join(cmd)}"
            )
        else:
            raise TsharkRunError(f"tshark pass {spec.name!r} kept hitting unknown preferences")
        rows = self._parse(proc.stdout, fields)
        if self.use_cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {"sha": self.sha, "fields": list(fields), "extra": list(extra_args), "rows": rows}
                )
            )
            tmp.replace(cache)
        self.stats[spec.name] = {"rows": len(rows), "cached": 0}
        return rows

    @staticmethod
    def _parse(stdout: str, fields: tuple[str, ...]) -> list[Row]:
        lines = stdout.splitlines()
        if not lines:
            return []
        header = lines[0].split(TAB)
        if header and header[0] == "frame.number":
            names = header
            body = lines[1:]
        else:
            names = list(fields)
            body = lines
        rows: list[Row] = []
        for line in body:
            if not line.strip():
                continue
            parts = line.split(TAB)
            row: Row = {}
            for i, name in enumerate(names):
                raw = parts[i] if i < len(parts) else ""
                row[name] = split_multi(raw)
            rows.append(row)
        return rows

    # -- public API --------------------------------------------------------
    def run(self, pass_name: str, extra_args: tuple[str, ...] = ()) -> list[Row]:
        spec = PASSES.get(pass_name)
        if spec is None:
            raise KeyError(f"unknown pass {pass_name!r}; known: {sorted(PASSES)}")
        return self._run(spec, extra_args)

    def all_passes(self) -> dict[str, list[Row]]:
        return {name: self._run(spec) for name, spec in PASSES.items()}

    @staticmethod
    def rtp_decode_args(ports: list[int]) -> tuple[str, ...]:
        """tshark only dissects RTP on well-known ports; SDP tells us the rest.

        Without this, media on dynamic ports shows up as plain UDP and the
        SRTP/plaintext verdict is impossible to make.
        """
        return tuple(f"-d udp.port=={port},rtp" for port in sorted(set(ports)) if 0 < port < 65536)

    def capture_stats(self) -> dict[str, str]:
        """capinfos-style facts, derived from the base pass (no extra process)."""
        base = self.run("base")
        packets = len(base)
        total_bytes = 0
        first = last = 0.0
        for row in base:
            for v in row.get("frame.len", []):
                total_bytes += int(v) if v.isdigit() else 0
            ts = to_float(row["frame.time_epoch"][0]) if row.get("frame.time_epoch") else None
            if ts is not None:
                if first == 0.0:
                    first = ts
                last = max(last, ts)
        return {
            "packets": str(packets),
            "bytes": str(total_bytes),
            "first": f"{first:.6f}",
            "last": f"{last:.6f}",
            "duration": f"{max(0.0, last - first):.6f}",
        }
