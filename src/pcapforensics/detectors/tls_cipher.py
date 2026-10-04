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
    "TLS 1.0": ("high", "TLS 1.0 is deprecated by RFC 8996 and banned by PCI DSS 4.0"),
    "TLS 1.1": ("high", "TLS 1.1 is deprecated by RFC 8996 and banned by PCI DSS 4.0"),
    "DTLS 1.0": ("high", "DTLS 1.0 is obsolete; RFC 9147 defines DTLS 1.2 and 1.3 only"),
}


def version_references(version: str) -> list[str]:
    """References for a deprecated-version finding: every RFC its text cites, plus the policy doc."""
    refs = ["RFC 8996", "RFC 9325"]
    if version.startswith("DTLS"):
        refs.append("RFC 9147")
    return [*refs, CIPHER_POLICY_DOC]


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
            findings += self._key_in_firmware(index, session, subjects)
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
        a TLS 1.2 or 1.3 session, so it is reported separately -- calling it
        "negotiated TLS 1.0" would be wrong.

        The separate record-layer finding is ``info``, not ``low``, and at
        ``medium`` confidence (#150). The compatibility sentinel is not an
        observation about this traffic, it is a constant of the protocol: RFC
        8446 has a TLS 1.3 ClientHello put 0x0301 in the record layer and tells
        readers to ignore it, and RFC 5246 does the same for the first record
        of a TLS 1.2 ClientHello. It only carries meaning on a post-handshake
        application record.

        This detector cannot make that call. ``TlsSession.record_versions`` is a
        de-duplicated list of version *names*: it keeps no frame number and no
        record content type, so a sentinel ClientHello and a downgraded
        application record leave an identical index. Reporting the value at
        ``low`` with ``high`` confidence claimed certainty about a non-issue.
        The finding still fires, so the downgrade case keeps its evidence; see
        docs/severity-model.md.
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
                    references=version_references(negotiated or ""),
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
                    title=(
                        f"Legacy {version} value in the record layer on {session.key} "
                        f"(session negotiated {negotiated or 'unknown'})"
                    ),
                    severity="info",
                    confidence="medium",
                    summary=(
                        f"A record in this session carries the legacy version value {version} while the "
                        f"session negotiated {negotiated or 'unknown'}. Before version negotiation that value "
                        "is the compatibility sentinel, not a statement about this session: RFC 8446 has a TLS "
                        "1.3 ClientHello put it in the record layer and says it MUST be ignored in favour of "
                        "supported_versions, and RFC 5246 does the same for the first record of a TLS 1.2 "
                        "ClientHello. It only carries meaning on a post-handshake application record, where a "
                        "peer that honours the legacy field would downgrade. This detector cannot separate the "
                        "two cases -- the index keeps the versions a session saw but not the record that carried "
                        "them -- so it is reported as inventory, not as a defect."
                    ),
                    scope=f"{session.key}|record|{version}",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[ev(self._client_hello_frame(session), "tls.record.version", version)],
                    remediation=(
                        "None for a ClientHello; that is the value the protocol mandates. To confirm this is not "
                        "a downgrade, look for a legacy version on an application-data record (content type "
                        "23) rather than a handshake record: "
                        "tshark -r <capture> -Y 'tls.record.content_type == 23 && tls.record.version < 0x0303'."
                    ),
                    references=["RFC 8446", "RFC 5246"],
                    tags=["tls", "version", "legacy", "expected"],
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
                    references=["RFC 8996", "RFC 7457", "RFC 9325", CIPHER_POLICY_DOC],
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

    def _key_in_firmware(
        self, index: CaptureIndex, session: TlsSession, subjects: list[str]
    ) -> list[Finding]:
        """A session cert whose public key matches a private key found in the supplied firmware.

        Whoever has the image has the key, so they can passively decrypt (and, as a MITM, tamper
        with) this channel on every device that ships it — forward secrecy or not.
        """
        if not index.firmware_keys:
            return []
        out: list[Finding] = []
        for cert in session.certs:
            fp = cert.spki_sha256
            if not fp or fp not in index.firmware_keys:
                continue
            path = index.firmware_keys[fp]
            out.append(
                self.finding(
                    code="TLS_KEY_IN_FIRMWARE",
                    title=f"Server key for {session.server} ships in the firmware",
                    severity="critical",
                    confidence="high",
                    summary=(
                        f"The certificate on {session.key} has public-key fingerprint {fp}, which matches a "
                        f"private key extracted from the supplied firmware ({path}). Anyone with the firmware "
                        "image holds this private key and can passively decrypt, and actively tamper with, this "
                        "channel on every device that ships it — no forward secrecy can help."
                    ),
                    scope=f"{session.key}|firmware-key",
                    flow_key=session.key,
                    subjects=subjects,
                    evidence=[
                        ev(self._server_hello_frame(session), "x509af.subjectPublicKey[spki_sha256]", fp),
                        ev(self._server_hello_frame(session), "firmware.private_key", path),
                    ],
                    remediation=(
                        "Provision a unique key pair per device (or per fleet) instead of shipping one private "
                        "key in the image; rotate the exposed key and revoke its certificate."
                    ),
                    references=["RFC 8446", CIPHER_POLICY_DOC],
                    tags=["tls", "firmware", "key-exposure"],
                )
            )
        return out

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

    It is equally wrong for DSA, whose size is a prime and not a modulus, so
    "below 2048 bits" means nothing there. DSA therefore gets its own branch that
    does not apply the RSA threshold, and says why (#152).

    An algorithm we could not identify is also not assumed to be RSA. The
    unknown case is handled *before* the RSA rule rather than after it, because
    after it the branch was unreachable for any key under 2048 bits: the RSA rule
    returned first and the evidence quietly claimed a DSA key, an Ed25519 key or
    an unnamed key was an RSA one.
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
    if not algo:
        if bits < 1024:
            return "high", ("The key algorithm could not be identified. This key is under 1024 bits, "
                            "below the breakable threshold whatever algorithm it is.")
        if bits < 2048:
            return "medium", ("The key algorithm could not be identified, so the 2048-bit RSA rule was "
                              "applied as the conservative choice.")
        return "medium", ("The key algorithm could not be identified. The key is at least 2048 bits, "
                          "which is acceptable for RSA but is not a verdict on an unknown algorithm.")
    if "ed25519" in algo or "ed448" in algo:
        # Fixed-parameter curves: there is no secret size to be small, so there is nothing here to
        # judge. Unreachable in practice -- openssl prints no "Public-Key: (N bit)" for these, so bits
        # is None and the guard above has already returned -- but reaching it would mean reporting a
        # fixed-curve key as a small RSA one, which is worse than the branch costs.
        return None
    if "dsa" in algo:
        # No citation is offered here on purpose: the size rule that follows from one is a prime
        # size, and docs/cipher-policy.md has no DSA tier to apply. Borrowing the RSA threshold would
        # be the exact error this branch exists to stop, so the key is reported and the gap named.
        return "medium", ("DSA key. A DSA prime size is not comparable with an RSA modulus, so the "
                          "RSA size policy does not apply to this key and pcap-doctor does not judge "
                          "its strength here. Treat DSA as needing review.")
    if bits < 1024:
        return "high", "RSA keys below 1024 bits are trivially factorable."
    if bits < 2048:
        return "medium", "RSA keys below 2048 bits are outside current guidance."
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
