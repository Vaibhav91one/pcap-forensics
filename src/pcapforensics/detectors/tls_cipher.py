"""D1 -- TLS/DTLS crypto posture.

Answers, per session: who talked to whom, what was offered, what was chosen,
which version, whether forward secrecy holds, what the certificate said, and
what an attacker gets if they break it later.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

from ..data_ciphers import (
    VERSION_RANK,
    classify,
    lookup,
    name_of,
    rank_suites,
    weakness_reasons,
)
from ..index import CaptureIndex
from ..models import Finding, Severity, TlsSession
from .base import Detector, ev

CIPHER_POLICY_DOC = "docs/cipher-policy.md"

VERSION_FINDING = {
    "SSL 3.0": ("critical", "SSL 3.0 is broken by POODLE (CVE-2014-3566)"),
    "TLS 1.0": ("high", "TLS 1.0 is deprecated by RFC 8999 and banned by PCI DSS 4.0"),
    "TLS 1.1": ("high", "TLS 1.1 is deprecated by RFC 8999 and banned by PCI DSS 4.0"),
    "DTLS 1.0": ("high", "DTLS 1.0 is obsolete; RFC 9147 defines DTLS 1.2 and 1.3 only"),
}


class TlsCipherDetector(Detector):
    name: ClassVar[str] = "d1.tls_cipher"
    title: ClassVar[str] = "TLS / DTLS cipher and certificate posture"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "crypto"
    description: ClassVar[str] = (
        "Detects deprecated protocol versions, weak or prohibited cipher suites, "
        "missing forward secrecy, and certificate weaknesses (expiry, key size, SAN)."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        for key, session in index.tls.items():
            flow = index.flows.get(key)
            subjects = self._subjects(index, session.key)
            _ = flow

            findings += self._version(session, subjects)
            findings += self._chosen_cipher(session, subjects)
            findings += self._offered_ciphers(session, subjects)
            findings += self._forward_secrecy(session, subjects)
            findings += self._certificates(session, subjects, index.capture.last_seen)
            findings += self._alerts(session, subjects)
            if session.truncated and flow is not None:
                findings += self._truncated(session, subjects)
        findings += self._fingerprint_clusters(index)
        return findings

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _subjects(index: CaptureIndex, key: str) -> list[str]:
        flow = index.flows.get(key)
        if flow is None:
            return []
        return [flow.endpoint_a, flow.endpoint_b]

    @staticmethod
    def _client_hello_frame(session: TlsSession) -> int:
        return session.client_hello.frame if session.client_hello else (session.frames[0] if session.frames else 0)

    @staticmethod
    def _server_hello_frame(session: TlsSession) -> int:
        return session.server_hello.frame if session.server_hello else 0

    # -- checks -------------------------------------------------------------
    def _version(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        """Two distinct facts, kept apart on purpose.

        ``negotiated_version`` is what both sides agreed on. A ClientHello's
        *record* version is a legacy field that routinely reads TLS 1.0 even on
        a TLS 1.2 or 1.3 session, so it is reported separately and at low
        severity -- calling it "negotiated TLS 1.0" would be wrong.
        """
        out: list[Finding] = []
        negotiated = session.negotiated_version
        rule = VERSION_FINDING.get(negotiated or "")
        if rule is not None:
            severity, why = rule
            out.append(
                self.finding(
                    code="TLS_VERSION_DEPRECATED",
                    title=f"{negotiated} negotiated on {session.key}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high" if session.complete else "medium",
                    summary=(
                        f"{session.server} completed a handshake at {negotiated}. {why}. "
                        f"Suite chosen: {name_of(session.chosen_cipher)}."
                    ),
                    scope=f"{session.key}|version|{negotiated}",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[
                        ev(
                            self._server_hello_frame(session) or self._client_hello_frame(session),
                            "tls.handshake.version",
                            negotiated,
                        ),
                        ev(
                            self._server_hello_frame(session),
                            "tls.handshake.ciphersuite",
                            name_of(session.chosen_cipher),
                        ),
                    ],
                    remediation="Raise the minimum to TLS 1.2 and prefer TLS 1.3; disable SSLv3/TLS1.0/1.1.",
                    references=["RFC 8996", "RFC 9325", CIPHER_POLICY_DOC],
                    tags=["tls", "version"],
                )
            )
        for version in session.record_versions:
            if version == negotiated or (rule is not None and version == negotiated):
                continue
            if version not in VERSION_FINDING:
                continue
            out.append(
                self.finding(
                    code="TLS_LEGACY_RECORD_VERSION",
                    title=f"{version} record-layer field on {session.key} (session is {negotiated or 'unknown'})",
                    severity="low",
                    confidence="high",
                    summary=(
                        f"A record in this session carries the legacy version field {version} while the "
                        f"negotiated version is {negotiated or 'unknown'}. This is normal for a ClientHello, "
                        "but some stacks also emit it on application records, which older peers downgrade to."
                    ),
                    scope=f"{session.key}|record|{version}",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[ev(self._client_hello_frame(session), "tls.record.version", version)],
                    remediation="No action unless the legacy version appears on post-handshake records.",
                    references=["RFC 8446"],
                    tags=["tls", "version", "legacy"],
                )
            )
        return out

    def _chosen_cipher(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        cipher = session.chosen_cipher
        if cipher is None:
            return []
        suite = lookup(cipher)
        frame = self._server_hello_frame(session) or self._client_hello_frame(session)
        if suite is None:
            return [
                self.finding(
                    code="TLS_CIPHER_UNKNOWN",
                    title=f"Unrecognised cipher suite 0x{cipher:04x}",
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"{session.server} negotiated cipher id 0x{cipher:04x}, which is not in the "
                        f"registry. Either a private/grease value or a registry gap. Treat as unreviewed."
                    ),
                    scope=f"{session.key}|{cipher}",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[ev(frame, "tls.handshake.ciphersuite", f"0x{cipher:04x}")],
                    remediation="Identify the value; if it is a GREASE/private value, confirm the peer honours RFC 8701 filtering.",
                    references=[CIPHER_POLICY_DOC],
                    tags=["tls", "cipher", "registry-gap"],
                )
            ]
        if suite.deprecation in {"prohibited", "deprecated"}:
            severity = "critical" if suite.deprecation == "prohibited" else "high"
            reasons = weakness_reasons(cipher)
            return [
                self.finding(
                    code="TLS_CIPHER_WEAK",
                    title=f"{suite.name} negotiated on {session.key}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    summary=(
                        f"{session.server} negotiated {suite.name} (0x{cipher:04x}). "
                        + "; ".join(reasons)
                        + f". Forward secrecy: {'yes' if session.forward_secrecy else 'no'}."
                    ),
                    scope=f"{session.key}|{cipher}",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[
                        ev(frame, "tls.handshake.ciphersuite", suite.name),
                        ev(
                            self._client_hello_frame(session),
                            "tls.handshake.ciphersuite[offered]",
                            f"{len(session.offered_ciphers)} suite(s) offered by the client",
                        ),
                    ],
                    remediation=_REMEDIATION.get(suite.deprecation, "Remove this suite from the server cipher list."),
                    references=["RFC 8996", "RFC 7457", CIPHER_POLICY_DOC],
                    tags=["tls", "cipher", suite.deprecation],
                )
            ]
        return []

    def _offered_ciphers(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        """Offered-but-never-chosen weak suites are downgrade surface."""
        if not session.offered_ciphers or not session.complete:
            return []
        chosen = session.chosen_cipher
        weak_offered = [
            cipher
            for cipher, suite in rank_suites(session.offered_ciphers)
            if suite is not None and cipher != chosen and suite.deprecation in {"prohibited", "deprecated"}
        ]
        if not weak_offered:
            return []
        frame = self._client_hello_frame(session)
        names = ", ".join(name_of(c) for c in weak_offered[:6])
        extra = f" (+{len(weak_offered) - 6} more)" if len(weak_offered) > 6 else ""
        return [
            self.finding(
                code="TLS_OFFERS_WEAK_CIPHERS",
                title=f"Client offers {len(weak_offered)} prohibited/deprecated suites",
                severity="medium",
                confidence="high",
                summary=(
                    f"The client hello on {session.key} offers weak suites that were not selected: {names}{extra}. "
                    "They are downgrade surface if a future negotiation or active attacker steers the choice."
                ),
                scope=f"{session.key}|offered",
                flow_key=session.key,
                subjects=subjects,
                evidence=[
                    ev(frame, "tls.handshake.ciphersuite[offered]", f"{len(session.offered_ciphers)} suites offered")
                ],
                remediation="Restrict the client cipher list to AEAD suites with ephemeral key exchange (TLS 1.3 recommended).",
                references=[CIPHER_POLICY_DOC],
                tags=["tls", "cipher", "downgrade"],
            )
        ]

    def _forward_secrecy(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        if session.forward_secrecy is not False:
            return []
        return [
            self.finding(
                code="TLS_NO_FORWARD_SECRECY",
                title=f"No forward secrecy on {session.key}",
                severity="high",
                confidence="high",
                summary=(
                    f"{session.server} used {name_of(session.chosen_cipher)} with a static key exchange "
                    f"({session.forward_secrecy_reason}). A later compromise of the server private key decrypts "
                    "all recorded past traffic on this session."
                ),
                scope=f"{session.key}|pfs",
                flow_key=session.key,
                subjects=subjects,
                evidence=[
                    item
                    for item in (
                        ev(
                            self._server_hello_frame(session),
                            "tls.handshake.ciphersuite",
                            name_of(session.chosen_cipher),
                        ),
                        ev(
                            self._client_hello_frame(session),
                            "tls.handshake.extensions_supported_group",
                            ", ".join(session.groups),
                        )
                        if session.groups
                        else None,
                    )
                    if item is not None and item.value
                ],
                remediation="Prefer ECDHE/DHE suites or TLS 1.3, which is PFS by construction.",
                references=["RFC 8446", CIPHER_POLICY_DOC],
                tags=["tls", "pfs"],
            )
        ]

    def _certificates(self, session: TlsSession, subjects: list[str], capture_end: float) -> list[Finding]:
        out: list[Finding] = []
        for cert in session.certs:
            scope = f"{session.key}|cert{cert.chain_index}"
            if cert.not_after:
                expiry = parse_ts(cert.not_after)
                if expiry is not None:
                    # Judge expiry against the capture window first: a certificate that
                    # was valid when the traffic happened is not an expired-certificate
                    # finding *about that traffic*, only a fact about today.
                    delta = expiry - datetime.now(UTC)
                    at_capture = expiry - datetime.fromtimestamp(capture_end, UTC)
                    expiry_severity: Severity
                    if at_capture.total_seconds() < 0:
                        expiry_severity = "high"
                        detail = f"had already expired {abs(int(at_capture.total_seconds() // 86400))} days before the capture"
                    elif delta.total_seconds() < 0:
                        expiry_severity = "low"
                        detail = (
                            f"was valid during the capture but expired "
                            f"{abs(int(delta.total_seconds() // 86400))} days ago"
                        )
                    elif at_capture.total_seconds() < 30 * 86400:
                        expiry_severity = "medium"
                        detail = f"expires {int(at_capture.total_seconds() // 86400)} days after the capture"
                    else:
                        continue
                    out.append(
                        self.finding(
                            code=(
                                "TLS_CERT_EXPIRED"
                                if expiry_severity == "high"
                                else "TLS_CERT_EXPIRED_NOW"
                                if expiry_severity == "low"
                                else "TLS_CERT_EXPIRING"
                            ),
                            title=f"Certificate {', '.join(cert.common_names) or f'#{cert.chain_index}'} {detail}",
                            severity=expiry_severity,
                            confidence="medium",
                            summary=(
                                f"Chain position {cert.chain_index} presented on {session.key} has validity "
                                f"{cert.not_before} .. {cert.not_after} ({detail}). Names seen in the "
                                f"certificate: {', '.join(cert.common_names) or 'n/a'}."
                            ),
                            scope=scope,
                            flow_key=session.key,
                            subjects=subjects,
                            evidence=[ev(cert.frame, "x509af.utcTime", f"{cert.not_before} .. {cert.not_after}")],
                            remediation="Renew and deploy the certificate; automate renewal and alerting.",
                            references=["RFC 5280"],
                            tags=["tls", "certificate"],
                        )
                    )
            weak_key = weak_key_verdict(cert.key_algorithm, cert.public_key_bits)
            if weak_key is not None:
                key_severity: Severity = weak_key[0]  # type: ignore[assignment]
                why = weak_key[1]
                out.append(
                    self.finding(
                        code="TLS_CERT_WEAK_KEY",
                        title=f"{cert.public_key_bits}-bit {cert.key_algorithm or 'public key'} on {session.key}",
                        severity=key_severity,
                        confidence="high" if cert.key_algorithm else "medium",
                        summary=(
                            f"Certificate chain position {cert.chain_index} uses a "
                            f"{cert.public_key_bits}-bit {cert.key_algorithm or 'unknown-algorithm'} key"
                            + (f" (curve {cert.key_curve})" if cert.key_curve else "")
                            + f". {why}"
                        ),
                        scope=f"{scope}|key",
                        flow_key=session.key,
                        subjects=subjects,
                        evidence=[
                            ev(
                                cert.frame,
                                "x509.subjectPublicKeyInfo",
                                f"{cert.key_algorithm or 'unknown'} {cert.public_key_bits} bits"
                                + (f" {cert.key_curve}" if cert.key_curve else ""),
                            )
                        ],
                        remediation="Reissue with at least a 2048-bit RSA key or a P-256 (or stronger) EC key.",
                        references=["NIST SP 800-57 Part 1 Rev. 5", "RFC 5280"],
                        tags=["tls", "certificate", "key-size"],
                    )
                )
            if cert.signature_algorithm_oid and _is_weak_sig(cert.signature_algorithm_oid):
                out.append(
                    self.finding(
                        code="TLS_CERT_WEAK_SIGALG",
                        title=f"Weak certificate signature algorithm on {session.key}",
                        severity="high",
                        confidence="high",
                        summary=(
                            f"Certificate chain position {cert.chain_index} is signed with "
                            f"{cert.signature_algorithm_oid}, which is collision-broken or withdrawn."
                        ),
                        scope=f"{scope}|sigalg",
                        flow_key=session.key,
                        subjects=subjects,
                        evidence=[ev(cert.frame, "x509af.algorithmId", cert.signature_algorithm_oid)],
                        remediation="Reissue with SHA-256 or stronger signatures.",
                        references=["RFC 6194", "RFC 9155"],
                        tags=["tls", "certificate"],
                    )
                )
        leaf_self_signed = bool(session.certs and session.certs[0].self_signed_suspected)
        if leaf_self_signed:
            leaf = session.certs[0]
            out.append(
                self.finding(
                    code="TLS_SELF_SIGNED_CHAIN",
                    title=f"Single self-signed certificate on {session.key}",
                    severity="medium",
                    confidence="low",
                    summary=(
                        f"The leaf certificate is self-signed: subject and issuer are both "
                        f"'{leaf.subject or ', '.join(leaf.common_names) or 'unknown'}'. Clients that pin or "
                        "validate the chain will reject it, and an on-path attacker can mint their own copy "
                        "of the identity with the same key."
                    ),
                    scope=f"{session.key}|selfsigned",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[
                        ev(leaf.frame, "x509.subject", leaf.subject or "n/a"),
                        ev(leaf.frame, "x509.issuer", leaf.issuer or "n/a"),
                    ],
                    remediation="Issue the leaf from a real CA, or pin the self-signed certificate deliberately.",
                    references=["RFC 5280"],
                    tags=["tls", "certificate", "self-signed"],
                )
            )
        return out

    def _alerts(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        out: list[Finding] = []
        for alert in session.alerts:
            fatal = alert.level == 2
            out.append(
                self.finding(
                    code="TLS_FATAL_ALERT" if fatal else "TLS_WARNING_ALERT",
                    title=f"TLS alert {alert.description} on {session.key}",
                    severity="medium" if fatal else "low",
                    confidence="high",
                    summary=(
                        f"Frame {alert.frame}: {'fatal' if fatal else 'warning'} alert "
                        f"{alert.description} (level {alert.level}) on {session.server}."
                    ),
                    scope=f"{session.key}|alert|{alert.frame}",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[ev(alert.frame, "tls.alert_message.desc", alert.description)],
                    remediation="Correlate with server logs; repeated handshake failures point at a scanner or misconfiguration.",
                    references=[],
                    tags=["tls", "alert"],
                )
            )
        return out

    def _truncated(self, session: TlsSession, subjects: list[str]) -> list[Finding]:
        return [
            self.finding(
                code="TLS_HANDSHAKE_TRUNCATED",
                title=f"Client hello without server hello on {session.key}",
                severity="low",
                confidence="medium",
                summary=(
                    f"{session.server} received a ClientHello (frame {self._client_hello_frame(session)}) but never "
                    "answered. Typical of a port scan, a firewall probe, or a capture that starts mid-handshake."
                ),
                scope=f"{session.key}|truncated",
                flow_key=session.key,
                subjects=subjects,
                evidence=[ev(self._client_hello_frame(session), "tls.handshake.type", "1")],
                remediation="Confirm whether the host is actually a TLS service; if not, close the port.",
                references=[],
                tags=["tls", "scan"],
            )
        ]

    def _fingerprint_clusters(self, index: CaptureIndex) -> list[Finding]:
        """JA3 grouping: one client fingerprint reused across many hosts is either a fleet or a scanner."""
        by_ja3: dict[str, list[str]] = {}
        for session in index.tls.values():
            if session.ja3:
                by_ja3.setdefault(session.ja3, []).append(session.key)
        out: list[Finding] = []
        for ja3, keys in by_ja3.items():
            hosts = {index.flows[k].endpoint_b for k in keys if k in index.flows}
            if len(keys) < 5 or len(hosts) < 3:
                continue
            first_frame = 0
            for key in keys:
                candidate = index.tls.get(key)
                if candidate is not None and candidate.frames:
                    first_frame = candidate.frames[0]
                    break
            out.append(
                self.finding(
                    code="TLS_JA3_FLEET",
                    title=f"JA3 {ja3[:12]}... seen on {len(hosts)} servers",
                    severity="info",
                    confidence="medium",
                    summary=(
                        f"One client TLS fingerprint ({ja3}) was used against {len(hosts)} distinct servers "
                        f"across {len(keys)} sessions. Typical of managed software or a scanner, but also of "
                        "malware with a hard-coded stack."
                    ),
                    scope=f"ja3|{ja3}",
                    subjects=sorted(hosts)[:20],
                    evidence=[ev(first_frame, "tls.handshake.ja3", ja3)],
                    remediation="Correlate the fingerprint with an inventory; add to allow/deny policy if unexpected.",
                    references=["JA3"],
                    tags=["tls", "fingerprint"],
                )
            )
        return out


_REMEDIATION = {
    "prohibited": "Remove this suite immediately; it is prohibited by policy. Rotate to TLS 1.3 or an AEAD ECDHE suite.",
    "deprecated": "Drop static-RSA suites; require ECDHE/DHE or TLS 1.3.",
    "legacy": "Migrate CBC/SHA-1 suites to AEAD (AES-GCM, ChaCha20-Poly1305) or TLS 1.3.",
}


def weak_key_verdict(algorithm: str | None, bits: int | None) -> tuple[str, str] | None:
    """Key-strength policy per algorithm.

    A blanket "fewer than 2048 bits is weak" rule is wrong for elliptic curves:
    P-384 is a 384-bit number that is stronger than RSA-2048. Getting this wrong
    turns every modern EC certificate into a false high-severity finding.
    """
    if not bits:
        return None
    algo = (algorithm or "").lower()
    if "ec" in algo or "ecdsa" in algo:
        if bits < 224:
            return "high", "Elliptic curves below 224 bits are outside current guidance."
        if bits < 256:
            return "medium", "P-224 is not recommended for new deployments; use P-256 or stronger."
        return None
    if bits < 1024:
        return "high", "RSA keys below 1024 bits are trivially factorable."
    if bits < 2048:
        return "medium", "RSA keys below 2048 bits are outside current guidance."
    if not algo:
        return "medium", "The key algorithm could not be identified; the 2048-bit rule was applied."
    return None


def _is_weak_sig(oid: str) -> bool:
    lowered = oid.lower()
    return any(token in lowered for token in ("md2", "md4", "md5", "sha1", "1.2.840.113549.1.1.5"))


def parse_ts(value: str) -> datetime | None:
    cleaned = value.replace(" (UTC)", "").strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S %Z",
        "%b %d %H:%M:%S %Y %Z",  # openssl: "Jan 17 23:00:00 2039 GMT"
        "%b %d %H:%M:%S %Y",
    ):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned).replace(tzinfo=UTC)
    except ValueError:
        return None


def version_ok(version: str) -> bool:
    return VERSION_RANK.get(version, -1) >= VERSION_RANK["TLS 1.2"]


def deprecation_of(cipher: int) -> str:
    return classify(cipher)
