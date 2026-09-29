"""D4 -- DNS, QUIC and SSH.

Three different questions:

* DNS -- what did we leak, and does the query volume look like tunnelling?
* QUIC -- which version, what is the TLS story inside it, is the payload opaque?
* SSH -- what algorithms were offered, and are any of them in the "no" list?
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict
from typing import ClassVar

from ..index import CaptureIndex
from ..models import DnsQuery, Finding
from .base import Detector, ev

LABEL_RE = re.compile(r"^[a-z0-9_\-*.]{1,63}$", re.IGNORECASE)

TUNNEL_MIN_LABELS = 4
TUNNEL_MIN_QTYPE = {"TXT": 12, "NULL": 8, "CNAME": 15}

WEAK_SSH_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha256",
    "rsa1024-sha1",
    "rsa2048-sha256",
}
WEAK_SSH_CIPHERS = {
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
    "arcfour",
    "arcfour256",
    "arcfour128",
    "blowfish-cbc",
    "cast128-cbc",
    "chacha20-poly1305@openssh.com",
}
WEAK_SSH_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
}
WEAK_SSH_HOSTKEYS = {"ssh-rsa", "ssh-dss", "ssh-rsa-sha256@libssh.org"}

RESOLVER_PORTS = frozenset({53, 853})


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class DnsQuicSshDetector(Detector):
    name: ClassVar[str] = "d4.dns_quic_ssh"
    title: ClassVar[str] = "DNS, QUIC and SSH posture"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "protocol"
    description: ClassVar[str] = (
        "Flags plaintext DNS leakage and tunnelling heuristics, inventories QUIC versions "
        "and its inner TLS, and checks SSH algorithm negotiation for weak options."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._dns_plaintext(index)
        findings += self._dns_tunnelling(index)
        findings += self._dns_bypass(index)
        findings += self._quic_inventory(index)
        findings += self._ssh_algorithms(index)
        return findings

    # -- DNS ----------------------------------------------------------------
    def _dns_plaintext(self, index: CaptureIndex) -> list[Finding]:
        groups: dict[str, list[DnsQuery]] = defaultdict(list)
        for query in index.dns:
            if query.over_tls or query.name.endswith(".arpa") or query.name.endswith(".local"):
                continue
            groups[query.key].append(query)
        out: list[Finding] = []
        for key, queries in groups.items():
            if not queries:
                continue
            flow = index.flows.get(key)
            if flow is None or flow.encrypted:
                continue
            unique = sorted({q.name for q in queries})
            resolver_port = sorted({p for p in (flow.port_a, flow.port_b)})
            out.append(
                self.finding(
                    code="DNS_CLEARTEXT",
                    title=f"{len(unique)} DNS name(s) resolved in cleartext via {key}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"{flow.endpoint_a}:{flow.port_a} asked {flow.endpoint_b}:{flow.port_b} "
                        f"(ports {resolver_port}) for {len(unique)} name(s) with no encryption. "
                        f"Examples: {', '.join(unique[:5])}"
                        + (f" (+{len(unique) - 5} more)" if len(unique) > 5 else "")
                        + ". Names and answers are visible to any on-path observer."
                    ),
                    scope=f"{key}|dns",
                    flow_key=key,
                    subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[
                        ev(q.frame, "dns.qry.name", f"{q.qtype} {q.name}") for q in queries[:5]
                    ],
                    remediation="Use DNS-over-TLS (853) or DNS-over-HTTPS, and enforce it in the resolver.",
                    references=["RFC 7858", "RFC 8484", "CWE-319"],
                    tags=["dns", "cleartext"],
                )
            )
        return out

    def _dns_tunnelling(self, index: CaptureIndex) -> list[Finding]:
        by_host: dict[str, list[DnsQuery]] = defaultdict(list)
        for query in index.dns:
            host = index.flows[query.key].endpoint_a if query.key in index.flows else "?"
            by_host[host].append(query)
        out: list[Finding] = []
        for host, queries in by_host.items():
            if len(queries) < TUNNEL_MIN_QTYPE["TXT"]:
                continue
            long_queries = [
                q for q in queries if q.name.count(".") >= TUNNEL_MIN_LABELS and all(LABEL_RE.match(p) for p in q.name.split(".") if p)
            ]
            txt = [q for q in queries if q.qtype.upper() in {"TXT", "NULL"}]
            unique_subdomains = {q.name.split(".")[0] for q in queries}
            if len(long_queries) + len(txt) < 12:
                continue
            entropies = [shannon_entropy(q.name.replace(".", "")) for q in long_queries]
            high_entropy = sum(1 for e in entropies if e > 3.5)
            severity = "high" if high_entropy >= 8 else "medium"
            out.append(
                self.finding(
                    code="DNS_TUNNEL_SHAPE",
                    title=f"{host} issued {len(queries)} DNS queries, {len(long_queries)} deeply-labelled",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="low" if high_entropy < 8 else "medium",
                    summary=(
                        f"{host} sent {len(queries)} DNS queries ({len(unique_subdomains)} distinct leading labels) "
                        f"to {index.flows[queries[0].key].endpoint_b if queries[0].key in index.flows else '?'}. "
                        f"{len(txt)} of type TXT/NULL, {len(long_queries)} with >= {TUNNEL_MIN_LABELS} labels, "
                        f"{high_entropy} of those above 3.5 bits/char entropy. That is the shape of DNS "
                        "tunnelling (iodine, dnscat) but also of aggressive CDN, RPKI or service discovery."
                    ),
                    scope=f"dns|{host}",
                    subjects=[host],
                    evidence=[
                        ev(q.frame, "dns.qry.name", f"{q.qtype} {q.name}") for q in (long_queries or txt)[:5]
                    ],
                    remediation="Inspect the queried names against an allowlist; block direct outbound DNS.",
                    references=["RFC 8484", "CWE-514"],
                    tags=["dns", "exfiltration", "heuristic"],
                )
            )
        return out

    def _dns_bypass(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        counts: Counter[str] = Counter()
        first_frame: dict[str, int] = {}
        for q in index.dns:
            if q.is_response or q.key not in index.flows:
                continue
            flow = index.flows[q.key]
            if flow.port_b in RESOLVER_PORTS:
                host = flow.endpoint_b
            elif flow.port_a in RESOLVER_PORTS:
                host = flow.endpoint_a
            else:
                continue
            counts[host] += 1
            prev = first_frame.get(host)
            if prev is None or q.frame < prev:
                first_frame[host] = q.frame
        for host, count in counts.most_common(10):
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if not (ip.is_global and not ip.is_multicast):
                continue
            first = first_frame[host]
            out.append(
                self.finding(
                    code="DNS_EXTERNAL_RESOLVER",
                    title=f"{host} answered {count} DNS queries (external resolver in use)",
                    severity="low",
                    confidence="medium",
                    summary=(
                        f"{count} queries in this capture were answered by the public resolver {host}. "
                        "Internal names may be leaked, and policy bypass is possible if the internal "
                        "resolver was meant to be authoritative."
                    ),
                    scope=f"dnsresolver|{host}",
                    subjects=[host],
                    evidence=[ev(first, "ipv6.dst" if ip.version == 6 else "ip.dst", host)],
                    remediation="Force DNS through the internal resolver; block outbound port 53/853 at the perimeter.",
                    references=["RFC 9076"],
                    tags=["dns", "policy"],
                )
            )
        return out

    # -- QUIC ---------------------------------------------------------------
    def _quic_inventory(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for session in index.quic:
            flow = index.flows.get(session.key)
            if flow is None:
                continue
            versions = ", ".join(session.versions) or "unknown"
            if not session.decryptable:
                out.append(
                    self.finding(
                        code="QUIC_PAYLOAD_OPAQUE",
                        title=f"QUIC on {session.key} is not decryptable ({versions})",
                        severity="info",
                        confidence="high",
                        summary=(
                            f"QUIC {versions} flow between {flow.endpoint_a}:{flow.port_a} and "
                            f"{flow.endpoint_b}:{flow.port_b}"
                            + (f" with SNI {session.sni}" if session.sni else "")
                            + ". Application data stays encrypted; a pass with an SSLKEYLOGFILE or QUIC "
                            "secrets is required to inspect payload or inner HTTP/3."
                        ),
                        scope=f"{session.key}|quic",
                        flow_key=session.key,
                        subjects=[flow.endpoint_a, flow.endpoint_b],
                        evidence=[ev(session.frame, "quic.version", versions)],
                        remediation="Provide a keylog to the analyzer; for detection purposes treat QUIC as encrypted.",
                        references=["RFC 9001", "RFC 9000"],
                        tags=["quic", "encrypted"],
                    )
                )
            if session.sni:
                index.add_note(f"[{self.name}] QUIC SNI observed: {session.sni} (frame {session.frame})")
        return out

    # -- SSH ----------------------------------------------------------------
    def _ssh_algorithms(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for session in index.ssh:
            flow = index.flows.get(session.key)
            if flow is None:
                continue
            subjects = [flow.endpoint_a, flow.endpoint_b]
            checks: list[tuple[str, list[str], set[str], str]] = [
                ("kex", session.kex_algorithms, WEAK_SSH_KEX, "key exchange"),
                ("cipher", session.ciphers, WEAK_SSH_CIPHERS - {"chacha20-poly1305@openssh.com"}, "cipher"),
                ("mac", session.macs, WEAK_SSH_MACS, "MAC"),
                ("hostkey", session.host_key_algorithms, WEAK_SSH_HOSTKEYS, "host key"),
            ]
            for kind, offered, weak, label in checks:
                hits = sorted(set(offered) & weak)
                if not hits:
                    continue
                severity = "high" if kind in {"kex", "cipher"} else "medium"
                out.append(
                    self.finding(
                        code=f"SSH_WEAK_{kind.upper()}",
                        title=f"SSH {label} negotiation includes {len(hits)} weak algorithm(s) on {session.key}",
                        severity=severity,  # type: ignore[arg-type]
                        confidence="high",
                        summary=(
                            f"{flow.endpoint_a}:{flow.port_a} <-> {flow.endpoint_b}:{flow.port_b} offered "
                            f"{len(offered)} {label}(s) including {', '.join(hits)}. These remain reachable if a "
                            "peer picks them, and some are directly exploitable (Terrapin, CVE-2023-48795)."
                        ),
                        scope=f"{session.key}|ssh|{kind}",
                        flow_key=session.key,
                        subjects=subjects,
                        evidence=[ev(session.frame, f"ssh.{kind}_algorithms", ", ".join(hits))],
                        remediation="Restrict Match/HostKeyAlgorithms in sshd_config and client config to modern algorithms.",
                        references=["RFC 9142", "CVE-2023-48795"],
                        tags=["ssh", "crypto"],
                    )
                )
            if session.compression and any(c.startswith("zlib") for c in session.compression):
                index.add_note(f"[{self.name}] SSH compression offered on {session.key}: {session.compression}")
        return out


def analyse_labels(name: str) -> dict[str, float | int]:
    labels = [p for p in name.split(".") if p]
    return {
        "labels": len(labels),
        "longest": max((len(p) for p in labels), default=0),
        "entropy": shannon_entropy(name.replace(".", "")),
    }
