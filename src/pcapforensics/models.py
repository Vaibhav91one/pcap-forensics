"""Frozen data contract shared by every detector and renderer.

Nothing in this module may be edited by detector subagents. New fields are
added by the core owner only (see AGENTS.md -> "Schema freeze").
"""

from __future__ import annotations

import hashlib
import math
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.6.0"
try:  # one source of truth: the installed distribution (pyproject.toml)
    TOOL_VERSION = version("pcap-doctor")
except PackageNotFoundError:  # running from a source tree that was never installed
    TOOL_VERSION = "0.0.0+unknown"

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]

SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Role(StrEnum):
    """Which side of a flow holds a given address/port."""

    SERVER = "server"
    CLIENT = "client"
    PEER = "peer"


class Evidence(BaseModel):
    """A single observable fact pulled out of tshark, always with a frame number."""

    frame: int
    field: str
    value: str


def flow_key(proto: str, a: str, ap: int, b: str, bp: int) -> str:
    """Direction-independent flow identity: sorted endpoint pair."""
    left = (a, ap)
    right = (b, bp)
    if right < left:
        left, right = right, left
    return f"{proto}:{left[0]}:{left[1]}<->{right[0]}:{right[1]}"


def endpoints_of(key: str) -> tuple[str, str, int, str, int]:
    """Inverse of :func:`flow_key`: ``(proto, ip_a, port_a, ip_b, port_b)``."""
    proto, rest = key.split(":", 1)
    left, right = rest.split("<->", 1)
    lh, lp = left.rsplit(":", 1)
    rh, rp = right.rsplit(":", 1)
    return proto, lh, int(lp), rh, int(rp)


def stable_id(*parts: object) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Flow(BaseModel):
    """A bidirectional conversation aggregated over all packets."""

    key: str
    proto: Literal["tcp", "udp"]
    endpoint_a: str
    port_a: int
    endpoint_b: str
    port_b: int
    app_proto: str = "unknown"
    packets: int = 0
    bytes: int = 0
    packets_a_to_b: int = 0
    bytes_a_to_b: int = 0
    first_seen: float = 0.0
    first_frame: int = 0
    burst_count: int = 0
    last_burst_start: float = 0.0
    burst_gap_mean: float = 0.0
    burst_gap_m2: float = 0.0
    last_seen: float = 0.0
    duration: float = 0.0
    stream_index: int | None = None
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    handshake_completed: bool | None = None
    encrypted: bool | None = None
    encryption_evidence: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @property
    def duration_human(self) -> str:
        if self.duration < 1e-6:
            return "0s"
        if self.duration < 1:
            return f"{self.duration * 1000:.0f}ms"
        if self.duration < 60:
            return f"{self.duration:.2f}s"
        if self.duration < 3600:
            return f"{self.duration / 60:.1f}m"
        return f"{self.duration / 3600:.1f}h"

    @property
    def burst_gap_cv(self) -> float | None:
        """Coefficient of variation of the gaps between bursts; None until there are two gaps."""
        gaps = self.burst_count - 1
        if gaps < 2 or self.burst_gap_mean <= 0:
            return None
        return math.sqrt(self.burst_gap_m2 / (gaps - 1)) / self.burst_gap_mean

    def endpoint_pairs(self) -> list[tuple[str, int, str, int, int, int]]:
        """Return (src, sport, dst, dport, bytes, packets) for both directions."""
        proto, a, ap, b, bp = endpoints_of(self.key)
        del proto
        return [
            (a, ap, b, bp, self.bytes_a_to_b, self.packets_a_to_b),
            (b, bp, a, ap, self.bytes - self.bytes_a_to_b, self.packets - self.packets_a_to_b),
        ]

    def matches_endpoint(self, ip: str, port: int | None = None) -> bool:
        for host, hport, _, _, _, _ in self.endpoint_pairs():
            if host == ip and (port is None or hport == port):
                return True
        return False


class Cert(BaseModel):
    """Certificate facts that tshark exposes. Subject/issuer split is best-effort."""

    chain_index: int
    common_names: list[str] = Field(default_factory=list)
    organizations: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    public_key_bits: int | None = None
    key_algorithm: str | None = None
    key_curve: str | None = None
    spki_sha256: str | None = None  # sha256(DER public key)[:16] — non-secret; matches a firmware key's SPKI
    signature_algorithm_oid: str | None = None
    san_dns: list[str] = Field(default_factory=list)
    subject: str | None = None
    issuer: str | None = None
    self_signed_suspected: bool = False
    name_source: str = "tshark-flattened"
    frame: int = 0


class Handshake(BaseModel):
    """ClientHello (type 1) or ServerHello (type 2) projection."""

    type: int
    frame: int
    legacy_version: str | None = None
    supported_versions: list[str] = Field(default_factory=list)
    cipher_suites: list[int] = Field(default_factory=list)
    cipher_suite: int | None = None
    compression_methods: list[int] = Field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = Field(default_factory=list)
    supported_groups: list[str] = Field(default_factory=list)
    sig_algs: list[str] = Field(default_factory=list)
    session_id: str | None = None
    ticket: bool = False
    downgrade_sentinel: str | None = None


class TlsAlert(BaseModel):
    frame: int
    level: int
    description: str


class RecordVersion(BaseModel):
    """One record's version field, with the frame that carried it (#157).

    `TlsSession.record_versions` used to be a de-duplicated list of version *names*, which made the
    ClientHello sentinel and a genuine post-handshake downgrade indistinguishable: RFC 8446 has a TLS
    1.3 ClientHello put 0x0301 in the record layer, and an older peer that honours the legacy field on
    application data downgrades the same way. The names were the same either way.

    Keeping the frame and the content type is what lets a detector tell those apart. Content type 22
    is handshake, 23 is application data.
    """

    frame: int
    version: str
    content_type: int | None = None  # 22 handshake, 23 application_data


class TlsSession(BaseModel):
    key: str
    proto: Literal["tls", "dtls"] = "tls"
    sni: str | None = None
    client_hello: Handshake | None = None
    server_hello: Handshake | None = None
    renegotiations: int = 0
    negotiated_version: str | None = None
    record_versions: list[RecordVersion] = Field(default_factory=list)
    chosen_cipher: int | None = None
    offered_ciphers: list[int] = Field(default_factory=list)
    alpn: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    forward_secrecy: bool | None = None
    forward_secrecy_reason: str | None = None
    resumption: bool | None = None
    ja3: str | None = None
    ja3s: str | None = None
    certs: list[Cert] = Field(default_factory=list)
    alerts: list[TlsAlert] = Field(default_factory=list)
    frames: list[int] = Field(default_factory=list)
    truncated: bool = False
    complete: bool = False

    @property
    def server(self) -> str:
        _, a, ap, b, bp = endpoints_of(self.key)
        return f"{a}:{ap} <-> {b}:{bp}"

    def direction_with(self, ip: str) -> str:
        _, a, ap, b, bp = endpoints_of(self.key)
        if a == ip:
            return f"{a}:{ap}"
        if b == ip:
            return f"{b}:{bp}"
        return f"{a}:{ap} <-> {b}:{bp}"

    def peer_of(self, ip: str) -> str:
        _, a, _ap, b, _bp = endpoints_of(self.key)
        return b if a == ip else a

    def ports(self) -> tuple[int, int]:
        _, _a, ap, _b, bp = endpoints_of(self.key)
        return ap, bp


class HttpExchange(BaseModel):
    key: str
    frame: int
    method: str | None = None
    host: str | None = None
    uri: str | None = None
    version: str | None = None
    status: int | None = None
    user_agent: str | None = None
    auth_scheme: str | None = None
    auth_present: bool = False
    auth_value_preview: str | None = None
    cookies_set: list[str] = Field(default_factory=list)
    cookie_flags_insecure: list[str] = Field(default_factory=list)
    body_frames: list[int] = Field(default_factory=list)
    is_encrypted: bool = False
    #: response headers that name what was delivered (#130): Content-Type values and Content-Disposition file names
    content_types: list[str] = Field(default_factory=list)
    download_names: list[str] = Field(default_factory=list)


class DnsQuery(BaseModel):
    key: str
    frame: int
    name: str
    qtype: str
    rcode: str | None = None
    answers: list[str] = Field(default_factory=list)
    is_response: bool = False
    over_tls: bool = False
    response_frame: int | None = None


class SipMessage(BaseModel):
    key: str
    frame: int
    kind: Literal["request", "response"]
    method: str | None = None
    status: int | None = None
    reason: str | None = None
    call_id: str | None = None
    cseq: str | None = None
    from_user: str | None = None
    to_user: str | None = None
    user_agent: str | None = None
    transport: str | None = None
    has_auth_header: bool = False
    auth_scheme: str | None = None
    sdp: str | None = None
    sdp_crypto_lines: list[str] = Field(default_factory=list)
    sdp_media: list[str] = Field(default_factory=list)
    sdp_protected: bool = False
    via_encrypted_transport: bool = False
    #: Observed source port of the message, used to reconstruct message direction.
    port_hint: int | None = None


class RtpStream(BaseModel):
    key: str
    ssrc: int | None = None
    payload_type: int | None = None
    payload_name: str | None = None
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    first_frame: int = 0
    last_seen: float = 0.0
    from_ip: str | None = None
    to_ip: str | None = None

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


class SshSession(BaseModel):
    key: str
    frame: int
    client_version: str | None = None
    server_version: str | None = None
    kex_algorithms: list[str] = Field(default_factory=list)
    host_key_algorithms: list[str] = Field(default_factory=list)
    ciphers: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    compression: list[str] = Field(default_factory=list)
    #: algorithm name -> KEXINIT frames that offered it
    offered_in: dict[str, list[int]] = Field(default_factory=dict)
    encrypted: bool = True


class QuicSession(BaseModel):
    key: str
    frame: int
    versions: list[str] = Field(default_factory=list)
    sni: str | None = None
    cipher_suites: list[int] = Field(default_factory=list)
    tls_versions: list[str] = Field(default_factory=list)
    alpn: list[str] = Field(default_factory=list)
    long_header_only: bool = True
    decryptable: bool = False


class ServiceHit(BaseModel):
    """Any other application protocol we recognise but do not model in depth."""

    key: str
    frame: int
    protocol: str
    detail: str | None = None
    sensitive: bool = False


class TelnetLogin(BaseModel):
    """A login typed over Telnet. The password itself is never stored: only its length and first frame."""

    key: str
    user: str | None = None
    user_frame: int | None = None
    password_length: int
    password_frame: int


class Host(BaseModel):
    ip: str
    flows: int = 0
    bytes: int = 0
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    roles: list[str] = Field(default_factory=list)
    asn_note: str | None = None


class Finding(BaseModel):
    id: str
    detector: str
    code: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    summary: str
    flow_key: str | None = None
    subjects: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @classmethod
    def make(
        cls,
        *,
        detector: str,
        code: str,
        title: str,
        severity: Severity,
        confidence: Confidence,
        category: str,
        summary: str,
        scope: str,
        evidence: list[Evidence] | None = None,
        subjects: list[str] | None = None,
        flow_key: str | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Finding:
        return cls(
            id=f"{detector}.{code}.{stable_id(scope, code, title)}",
            detector=detector,
            code=code,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            summary=summary,
            flow_key=flow_key,
            subjects=subjects or [],
            evidence=evidence or [],
            remediation=remediation,
            references=references or [],
            tags=tags or [],
        )


class CaptureInfo(BaseModel):
    path: str
    name: str
    sha256: str
    size_bytes: int
    packets: int
    bytes: int
    first_seen: float
    last_seen: float
    duration: float
    link_type: str | None = None
    tshark_version: str = ""


class ArtifactRef(BaseModel):
    name: str
    path: str
    kind: Literal["markdown", "json"]


class Stats(BaseModel):
    packets: int = 0
    bytes: int = 0
    flows: int = 0
    encrypted_flows: int = 0
    cleartext_flows: int = 0
    unknown_flows: int = 0
    hosts: int = 0
    tls_sessions: int = 0
    quic_sessions: int = 0
    sip_messages: int = 0
    rtp_streams: int = 0
    dns_queries: int = 0
    http_exchanges: int = 0
    ssh_sessions: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_detector: dict[str, int] = Field(default_factory=dict)
    app_protocols: dict[str, int] = Field(default_factory=dict)


class Report(BaseModel):
    schema_version: str = SCHEMA_VERSION
    tool_version: str = TOOL_VERSION
    generated_at: str
    capture: CaptureInfo
    stats: Stats
    flows: list[Flow]
    tls_sessions: list[TlsSession]
    findings: list[Finding]
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    detector_versions: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
