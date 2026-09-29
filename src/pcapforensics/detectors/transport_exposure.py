"""D2 -- plaintext transport exposure.

Credentials, cookies and protocol states that cross the network without
encryption, plus the shapes that reconnaissance traffic leaves behind.
"""

from __future__ import annotations

from collections import Counter
from typing import ClassVar

from ..index import WELL_KNOWN_PORTS, CaptureIndex
from ..models import Finding, ServiceHit
from .base import Detector, ev

#: Request methods that normally carry state worth protecting.
SENSITIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "PROPFIND", "MKCOL"}

#: Well-known encrypted and web ports. A cleartext protocol on a port above 1024
#: that is not on this list gets a second look.
ODD_PORT_SKIP = {80, 443, 8080, 8443, 5060, 5061, 5353, 853, 784, 8853}

#: A beacon is a scheduled callback: require enough burst gaps to measure a rate
#: distribution, and require that distribution to be tight (issue #10).
BEACON_MIN_GAPS = 5
BEACON_MAX_CV = 0.1


class TransportExposureDetector(Detector):
    name: ClassVar[str] = "d2.transport_exposure"
    title: ClassVar[str] = "Plaintext transport exposure"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "cleartext"
    description: ClassVar[str] = (
        "Finds credentials and sensitive state sent without TLS: HTTP Basic/Digest auth, "
        "insecure cookies, FTP/Telnet/SNMP/LDAP/Redis/MySQL, scan-shaped TCP patterns."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._http_auth(index)
        findings += self._http_cookies(index)
        findings += self._cleartext_services(index)
        findings += self._service_credentials(index)
        findings += self._nonstandard_ports(index)
        findings += self._syn_only(index)
        findings += self._beaconing(index)
        return findings

    # -- HTTP ---------------------------------------------------------------
    def _http_auth(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for exch in index.http:
            if not exch.auth_present:
                continue
            scheme = (exch.auth_scheme or "?").lower()
            if exch.is_encrypted:
                if scheme == "basic":
                    out.append(
                        self.finding(
                            code="HTTP_BASIC_AUTH",
                            title=f"HTTP Basic auth on {exch.key}",
                            severity="low",
                            confidence="high",
                            summary=(
                                f"{exch.method or 'request'} {exch.host or ''}{exch.uri or ''} uses HTTP Basic auth. "
                                "Inside TLS this is only as strong as the transport; the credential is still "
                                "replayable if the session key leaks."
                            ),
                            scope=f"{exch.key}|basic",
                            flow_key=exch.key,
                            subjects=self._subjects(index, exch.key),
                            evidence=[
                                ev(exch.frame, "http.request.method", exch.method),
                                ev(exch.frame, "http.authorization", exch.auth_value_preview or scheme),
                            ],
                            remediation="Prefer token/OAuth bearer auth with short expiry over Basic.",
                            references=["RFC 7617"],
                            tags=["http", "auth"],
                        )
                    )
                continue
            severity = "critical" if scheme == "basic" else "high"
            out.append(
                self.finding(
                    code="HTTP_CLEARTEXT_AUTH",
                    title=f"{scheme.title()} credentials in cleartext on {exch.key}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    summary=(
                        f"{exch.method or 'request'} {exch.host or ''}{exch.uri or ''} sent a "
                        f"{scheme} Authorization header without TLS. Anyone on-path can read or replay it."
                    ),
                    scope=f"{exch.key}|auth",
                    flow_key=exch.key,
                    subjects=self._subjects(index, exch.key),
                    evidence=[
                        ev(exch.frame, "http.request.method", exch.method),
                        ev(exch.frame, "http.authorization", exch.auth_value_preview or scheme),
                        ev(exch.frame, "http.host", exch.host or "n/a"),
                    ],
                    remediation="Terminate TLS, or move to a token scheme; never send Basic over cleartext.",
                    references=["RFC 7617", "CWE-319"],
                    tags=["http", "auth", "cleartext"],
                )
            )
        return out

    def _http_cookies(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for exch in index.http:
            if not exch.cookie_flags_insecure or exch.is_encrypted:
                continue
            if exch.status and exch.status >= 400:
                continue
            names = ", ".join(exch.cookie_flags_insecure[:8])
            out.append(
                self.finding(
                    code="HTTP_COOKIE_NO_SECURE",
                    title=f"Session cookie without Secure flag on {exch.key}",
                    severity="high",
                    confidence="medium",
                    summary=(
                        f"{exch.host or 'server'} set cookie(s) {names} over cleartext HTTP with no Secure flag, "
                        "so they will travel in the clear and leak on any later plaintext request."
                    ),
                    scope=f"{exch.key}|cookie",
                    flow_key=exch.key,
                    subjects=self._subjects(index, exch.key),
                    evidence=[ev(exch.frame, "http.set_cookie", names)],
                    remediation="Set Secure, HttpOnly and SameSite on every session cookie, and serve the site over HTTPS only.",
                    references=["CWE-614", "OWASP Session Management"],
                    tags=["http", "cookie"],
                )
            )
        return out

    # -- other cleartext services -----------------------------------------
    def _cleartext_services(self, index: CaptureIndex) -> list[Finding]:
        grouped: dict[tuple[str, str], list[ServiceHit]] = {}
        for hit in index.services:
            if not hit.sensitive:
                continue
            grouped.setdefault((hit.key, hit.protocol), []).append(hit)
        out: list[Finding] = []
        for (key, protocol), hits in grouped.items():
            flow = index.flows.get(key)
            if flow is None or flow.encrypted:
                continue
            ports = sorted({p for p in (flow.port_a, flow.port_b)})
            frames = [h.frame for h in hits[:5]]
            out.append(
                self.finding(
                    code="CLEARTEXT_SERVICE",
                    title=f"{protocol.upper()} traffic in cleartext on ports {ports}",
                    severity="high" if protocol in {"ftp", "telnet", "ldap", "redis", "mysql"} else "medium",
                    confidence="high",
                    summary=(
                        f"{len(hits)} {protocol} message(s) observed in cleartext between "
                        f"{flow.endpoint_a}:{flow.port_a} and {flow.endpoint_b}:{flow.port_b}. "
                        f"First detail: {hits[0].detail}"
                    ),
                    scope=f"{key}|{protocol}",
                    flow_key=key,
                    subjects=self._subjects(index, key),
                    evidence=[ev(f, f"{protocol}.detail", hits[i].detail) for i, f in enumerate(frames)],
                    remediation=(
                        "Move to the encrypted variant (SFTP, FTPS, LDAPS, TLS-wrapped Redis/MySQL) or tunnel the traffic."
                    ),
                    references=["CWE-319"],
                    tags=["cleartext", protocol],
                )
            )
        return out

    def _service_credentials(self, index: CaptureIndex) -> list[Finding]:
        labels = {
            "snmp.community": "SNMP community",
            "ldap.simple": "LDAP bind password",
            "mysql.query": "MySQL query",
            "ftp.request.arg": "FTP password",
        }
        out: list[Finding] = []
        for hit in index.services:
            fields: dict[str, str] = {}
            for part in (hit.detail or "").split(" | "):
                if "=" in part:
                    name, _, raw_value = part.partition("=")
                    fields[name] = raw_value
            command = (fields.get("ftp.request.command") or "").upper()
            for field in ("snmp.community", "ldap.simple", "mysql.query", "ftp.request.arg"):
                if field == "ftp.request.arg" and command != "PASS":
                    continue
                value: str | None = fields.get(field)
                if not value:
                    continue
                out.append(
                    self.finding(
                        code="CLEARTEXT_CREDENTIAL",
                        title=f"{labels[field]} exposed in cleartext on {hit.key}",
                        severity="critical",
                        confidence="high",
                        summary=(
                            f"Frame {hit.frame}: {field}={value!r} was observed in cleartext. "
                            "Treat this credential as compromised and rotate it."
                        ),
                        scope=f"{hit.key}|cred|{field}|{hit.frame}",
                        flow_key=hit.key,
                        subjects=self._subjects(index, hit.key),
                        evidence=[ev(hit.frame, field, value)],
                        remediation="Rotate the credential and require an encrypted transport with authentication.",
                        references=["CWE-319", "CWE-798"],
                        tags=["cleartext", "credential"],
                    )
                )
        return out

    # -- network shape ------------------------------------------------------
    def _nonstandard_ports(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        for flow in index.flows.values():
            if flow.encrypted or flow.app_proto not in {"ftp", "telnet", "tftp", "ntp", "smtp", "ldap", "mysql", "redis"}:
                continue
            # tftp transfers run on ephemeral ports by design (RFC 1350): its data
            # connections never indicate a service on an odd port.
            if flow.app_proto == "tftp":
                continue
            if any(p < 1024 or p in ODD_PORT_SKIP or p in WELL_KNOWN_PORTS for p in (flow.port_a, flow.port_b)):
                continue
            host, port, peer, peer_port = (
                (flow.endpoint_a, flow.port_a, flow.endpoint_b, flow.port_b)
                if flow.port_a <= flow.port_b
                else (flow.endpoint_b, flow.port_b, flow.endpoint_a, flow.port_a)
            )
            out.append(
                self.finding(
                    code="SERVICE_ON_ODD_PORT",
                    title=f"{flow.app_proto} on non-standard port {port} without TLS",
                    severity="medium",
                    confidence="low",
                    summary=(
                        f"{host} is serving {flow.app_proto} on port {port} (peer {peer}:{peer_port}) "
                        "with no encryption layer detected."
                    ),
                    scope=f"{flow.key}|port",
                    flow_key=flow.key,
                    subjects=[host],
                    evidence=[ev(flow.first_frame, f"{flow.proto}.port", f"{host}:{port}")],
                    remediation="Confirm the service is intended here; if so, wrap it in TLS and firewall the port.",
                    references=[],
                    tags=["network", "exposure"],
                )
            )
        return out

    def _syn_only(self, index: CaptureIndex) -> list[Finding]:
        counts: Counter[str] = Counter()
        first_frames: dict[str, int] = {}
        for flow in index.flows.values():
            if flow.proto == "tcp" and flow.handshake_completed is False:
                counts[flow.endpoint_a] += 1
                if flow.first_frame and (
                    flow.endpoint_a not in first_frames or flow.first_frame < first_frames[flow.endpoint_a]
                ):
                    first_frames[flow.endpoint_a] = flow.first_frame
        out: list[Finding] = []
        for ip, count in counts.most_common(10):
            if count < 5:
                continue
            out.append(
                self.finding(
                    code="SYN_SCAN_SHAPE",
                    title=f"{ip} sent {count} connection attempts that were never answered",
                    severity="medium",
                    confidence="medium",
                    summary=(
                        f"{ip} opened {count} TCP conversations that never completed a handshake, which is the "
                        "signature of a port scan or a host with a filtered port range."
                    ),
                    scope=f"synscan|{ip}",
                    subjects=[ip],
                    evidence=[ev(first_frames.get(ip, 0), "tcp.flags.syn", f"{count} unanswered SYNs")],
                    remediation="Block or rate-limit the source; if this was authorised testing, record the window.",
                    references=[],
                    tags=["network", "scan"],
                )
            )
        return out

    def _beaconing(self, index: CaptureIndex) -> list[Finding]:
        """Near-constant gaps between bursts on one flow = scheduled callback."""
        out: list[Finding] = []
        for flow in index.flows.values():
            cv = flow.burst_gap_cv
            if cv is None or flow.burst_count - 1 < BEACON_MIN_GAPS or cv > BEACON_MAX_CV:
                continue
            period = flow.burst_gap_mean
            out.append(
                self.finding(
                    code="BEACONING_SHAPE",
                    title=f"Regular callbacks on {flow.key} (every {period:.1f}s)",
                    severity="medium",
                    confidence="low",
                    summary=(
                        f"{flow.endpoint_a}:{flow.port_a} <-> {flow.endpoint_b}:{flow.port_b} carried {flow.burst_count} bursts of traffic "
                        f"{period:.1f}s apart (coefficient of variation {cv:.2f}), which matches implant-style periodic check-ins. "
                        "Timing alone cannot tell a beacon from a scheduled job; confirm against known schedules."
                    ),
                    scope=f"{flow.key}|beacon",
                    flow_key=flow.key,
                    subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[ev(flow.first_frame, "frame.time_epoch", f"period {period:.1f}s, cv {cv:.2f}, {flow.burst_count} bursts")],
                    remediation="Correlate the interval with known job schedules; if unexplained, isolate the host.",
                    references=[],
                    tags=["network", "beaconing"],
                )
            )
        return out

    @staticmethod
    def _subjects(index: CaptureIndex, key: str) -> list[str]:
        flow = index.flows.get(key)
        return [flow.endpoint_a, flow.endpoint_b] if flow else []
