"""Markdown renderers: the four report artifacts plus the index page.

Artifacts, in order:

1. ``01-flows.md``    -- who talked to whom, volume, duration, encryption state
2. ``02-ciphers.md``  -- the crypto matrix, per sender/recipient
3. ``03-findings.md`` -- security issues, worst first, with evidence
4. ``04-diagrams.md`` -- Mermaid topology, cipher graph, severity, media timeline
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..data_ciphers import name_of, registry_provenance, weakness_reasons
from ..index import CaptureIndex
from ..models import (
    SEVERITY_ORDER,
    Finding,
    Flow,
    Report,
    SipMessage,
    TlsSession,
    endpoints_of,
)
from ..prompts import clean
from . import mermaid

SEVERITY_BADGE = {
    "critical": "🔴 critical",
    "high": "🟠 high",
    "medium": "🟡 medium",
    "low": "🔵 low",
    "info": "⚪ info",
}

ENCRYPTION_LABEL = {True: "encrypted", False: "**cleartext**", None: "unknown"}


#: Report values are longer than prompt values: a summary sentence in a report is meant to be read in
#: full, while a prompt fact is a label. The sanitiser is the one the prompt and the JSON envelope
#: already use -- capture text is attacker-controlled, and this renderer was the place that printed
#: it without going through that (#167).
CAPTURE_VALUE_LIMIT = 400


def _capture_text(value: str) -> str:
    # Capture-controlled text on its way into a Markdown artifact.
    #
    # report.json and the AI prompt were already clean because both route through prompts.clean().
    # 03-findings.md built its own sentences and did not, so an HTTP Host header could put a raw
    # ANSI escape -- including a screen clear and a red "no findings" -- into the file the README
    # tells people to paste into a ticket. This is the same call, not a new sanitiser.
    return clean(value, limit=CAPTURE_VALUE_LIMIT).replace("|", chr(92) + "|")


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.confidence.count("high"), f.detector, f.code),
    )


def _ts(value: float) -> str:
    if not value:
        return "-"
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M:%S")


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") for c in row]
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    return "\n".join(out)


def _write(path: Path, text: str) -> Path:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------- index page
def render_index(report: Report, index: CaptureIndex) -> Path:
    stats = report.stats
    lines: list[str] = []
    cap = report.capture
    lines += [
        f"# Capture report -- {cap.name}",
        "",
        f"_Generated {report.generated_at} by pcap-doctor {report.tool_version} "
        f"(schema {report.schema_version}, tshark {cap.tshark_version})._",
        "",
        "## At a glance",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["File", f"`{cap.path}`"],
                ["SHA-256", f"`{cap.sha256}`"],
                ["Size", f"{cap.size_bytes / 1024:.1f} KiB"],
                ["Packets", f"{cap.packets:,}"],
                ["Bytes on wire", f"{cap.bytes:,}"],
                ["Window", f"{_ts(cap.first_seen)} .. {_ts(cap.last_seen)} ({cap.duration:.1f}s)"],
                ["Flows", f"{stats.flows}"],
                ["Hosts (IPs)", f"{stats.hosts}"],
                [
                    "Encrypted / cleartext / unknown",
                    f"{stats.encrypted_flows} / {stats.cleartext_flows} / {stats.unknown_flows}",
                ],
                ["TLS sessions", f"{stats.tls_sessions}"],
                ["QUIC sessions", f"{stats.quic_sessions}"],
                ["SIP messages", f"{stats.sip_messages}"],
                ["RTP streams", f"{stats.rtp_streams}"],
                ["DNS queries", f"{stats.dns_queries}"],
                ["HTTP exchanges", f"{stats.http_exchanges}"],
                ["SSH sessions", f"{stats.ssh_sessions}"],
            ],
        ),
        "## Findings",
        "",
    ]
    if report.findings:
        worst = _sorted_findings(report.findings)
        head = [f for f in worst if f.severity in {"critical", "high"}][:8]
        if head:
            lines.append("**Needs attention first**")
            lines.append("")
            for finding in head:
                lines.append(f"- {SEVERITY_BADGE[finding.severity]} [{finding.title}](03-findings.md#{_anchor(finding)})")
            lines.append("")
        lines.append(_table(
            ["Severity", "Count"],
            [[SEVERITY_BADGE.get(s, s), str(count)] for s, count in stats.findings_by_severity.items()],
        ))
    else:
        lines += ["_No findings were raised. That is not proof of safety: this tool only sees what the "
                  "capture contains. See `notes` below._", ""]
    lines += [
        "## Artifacts",
        "",
        _table(
            ["Artifact", "Contains"],
            [
                ["[`01-flows.md`](01-flows.md)", "every conversation, volume, encryption verdict"],
                ["[`02-ciphers.md`](02-ciphers.md)", "negotiated crypto per sender/recipient, cert facts"],
                ["[`03-findings.md`](03-findings.md)", "security issues with evidence and remediation"],
                ["[`04-diagrams.md`](04-diagrams.md)", "Mermaid topology, cipher graph, severity, media"],
                ["[`report.json`](report.json)", "everything above, machine readable"],
            ],
        ),
        "## Detectors that ran",
        "",
        _table(
            ["Detector", "Version", "Findings"],
            [[name, version, str(stats.findings_by_detector.get(name, 0))] for name, version in report.detector_versions.items()],
        ),
    ]
    notes = list(report.notes) + list(getattr(index, "notes", []))
    if notes:
        lines += ["## Notes and limitations", ""] + [f"- {n}" for n in notes] + [""]
    lines += [
        "## Cipher policy provenance",
        "",
        *[f"- {p}" for p in registry_provenance()],
        "",
    ]
    return _write(Path(report.artifacts[0].path).parent / "index.md", "\n".join(lines))


# ------------------------------------------------------------------- flows
def render_flows(report: Report, index: CaptureIndex) -> Path:
    flows = sorted(index.flows.values(), key=lambda f: (-f.bytes, f.key))
    lines = [
        f"# 01 -- Flows in {report.capture.name}",
        "",
        f"{len(flows)} conversations, {report.stats.packets:,} packets, {report.capture.bytes:,} bytes.",
        "",
        "## Summary by application protocol",
        "",
        _table(["App protocol", "Flows"], [[k, str(v)] for k, v in report.stats.app_protocols.items()]),
        "## Hosts",
        "",
        _table(
            ["IP", "Flows", "Packets", "Bytes", "First seen", "Last seen"],
            [
                [h.ip, str(h.flows), f"{h.packets:,}", f"{h.bytes:,}", _ts(h.first_seen), _ts(h.last_seen)]
                for h in sorted(index.hosts.values(), key=lambda x: -x.bytes)[:60]
            ],
        ),
        "## Conversations",
        "",
    ]
    rows = []
    for flow in flows:
        _p, a, ap, b, bp = endpoints_of(flow.key)
        server, sport, client, cport = _orient(flow)
        rows.append(
            [
                f"`{a}:{ap}` <-> `{b}:{bp}`",
                flow.proto,
                flow.app_proto,
                f"`{client}:{cport}` -> `{server}:{sport}`",
                f"{flow.packets:,}",
                f"{flow.bytes:,}",
                flow.duration_human,
                ENCRYPTION_LABEL[flow.encrypted],
                ", ".join(flow.encryption_evidence[:2]) or "-",
            ]
        )
    lines.append(
        _table(
            ["Conversation", "L4", "App", "Orientation", "Packets", "Bytes", "Duration", "Crypto", "Evidence"],
            rows,
        )
    )
    clear = [f for f in flows if f.encrypted is False]
    if clear:
        lines += ["## Cleartext conversations", ""]
        lines.append(_table(
            ["Conversation", "App", "Bytes", "Why"],
            [
                [f"`{f.endpoint_a}:{f.port_a}` <-> `{f.endpoint_b}:{f.port_b}`", f.app_proto, f"{f.bytes:,}",
                 ", ".join(f.encryption_evidence) or "no TLS detected"]
                for f in sorted(clear, key=lambda f: -f.bytes)[:40]
            ],
        ))
    return _write(Path(report.artifacts[0].path).parent / "01-flows.md", "\n".join(lines))


def _orient(flow: Flow) -> tuple[str, int, str, int]:
    server_ports = {21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 389, 443, 445, 5060, 5061, 3306, 6379}
    if flow.port_a in server_ports or flow.port_b not in server_ports:
        return flow.endpoint_a, flow.port_a, flow.endpoint_b, flow.port_b
    return flow.endpoint_b, flow.port_b, flow.endpoint_a, flow.port_a


# ----------------------------------------------------------------- ciphers
def render_ciphers(report: Report, index: CaptureIndex) -> Path:
    sessions = sorted(index.tls.values(), key=lambda s: (s.key))
    lines = [
        f"# 02 -- Negotiated cryptography in {report.capture.name}",
        "",
        f"{len(sessions)} TLS/DTLS session(s) observed. Matrix is *sender -> recipient*: the client is on "
        "the left, the responder on the right.",
        "",
    ]
    if not sessions:
        lines += ["_No TLS or DTLS handshake was visible in this capture._", ""]
    rows = []
    for session in sessions:
        _p, a, ap, b, bp = endpoints_of(session.key)
        client, cport, server, sport = _orient_session(a, ap, b, bp)
        rows.append(
            [
                f"`{client}:{cport}`",
                f"`{server}:{sport}`",
                session.proto.upper(),
                session.negotiated_version
                or (session.record_versions[0].version if session.record_versions else "-"),
                f"`{name_of(session.chosen_cipher)}`",
                str(len(session.offered_ciphers)),
                _pfs(session),
                ", ".join(session.alpn) or "-",
                session.sni or "-",
                _cert_line(session),
            ]
        )
    lines.append(
        _table(
            ["Sender", "Recipient", "Proto", "Version", "Chosen suite", "Offered", "PFS", "ALPN", "SNI", "Certificate"],
            rows,
        )
    )
    lines += ["## Offered suites per session", ""]
    for session in sessions:
        _p, a, ap, b, bp = endpoints_of(session.key)
        offered = ", ".join(f"{name_of(c)} (0x{c:04x})" for c in session.offered_ciphers[:24]) or "not visible"
        if len(session.offered_ciphers) > 24:
            offered += f" ... +{len(session.offered_ciphers) - 24}"
        lines += [
            f"### `{a}:{ap}` <-> `{b}:{bp}`",
            "",
            f"- Negotiated version: {session.negotiated_version or 'unknown'}",
            f"- Record versions seen: "
            f"{', '.join(dict.fromkeys(r.version for r in session.record_versions)) or 'none'}",
            f"- Chosen suite: `{name_of(session.chosen_cipher)}` (id 0x{session.chosen_cipher:04x})"
            if session.chosen_cipher is not None
            else "- Chosen suite: not observed",
            f"- Forward secrecy: {_pfs(session)}",
            f"- Handshake complete: {session.complete}",
            f"- Offered ({len(session.offered_ciphers)}): {offered}",
            f"- SNI: {session.sni or '-'}   ALPN: {', '.join(session.alpn) or '-'}",
            f"- JA3: `{session.ja3 or '-'}`   JA3S: `{session.ja3s or '-'}`",
        ]
        if session.certs:
            lines.append("- Certificate chain:")
            for cert in session.certs:
                lines.append(
                    f"  - #{cert.chain_index} CN={', '.join(cert.common_names) or 'n/a'} "
                    f"valid {cert.not_before or '?'} .. {cert.not_after or '?'} "
                    f"key={cert.public_key_bits or 'n/a'}b sig={cert.signature_algorithm_oid or 'n/a'} "
                    f"san={', '.join(cert.san_dns) or 'none'}"
                )
        if session.alerts:
            lines.append(
                "- Alerts: " + ", ".join(f"frame {a_.frame} {a_.description}" for a_ in session.alerts[:6])
            )
        if session.chosen_cipher is not None and weakness_reasons(session.chosen_cipher):
            lines.append("- Weakness notes: " + "; ".join(weakness_reasons(session.chosen_cipher)))
        lines.append("")
    if index.quic:
        lines += ["## QUIC (crypto is inside the encrypted envelope)", ""]
        lines.append(
            _table(
                ["Conversation", "QUIC version", "SNI", "TLS versions offered", "Decryptable"],
                [
                    [
                        f"`{q.key}`",
                        ", ".join(q.versions) or "-",
                        q.sni or "-",
                        ", ".join(q.tls_versions) or "-",
                        "yes" if q.decryptable else "no (no keylog)",
                    ]
                    for q in index.quic
                ],
            )
        )
    if index.ssh:
        lines += ["## SSH algorithm negotiation", ""]
        for ssh in index.ssh:
            lines += [
                f"### `{ssh.key}`",
                "",
                f"- client: {ssh.client_version or '?'} / server: {ssh.server_version or '?'}",
                f"- kex ({len(ssh.kex_algorithms)}): {', '.join(ssh.kex_algorithms) or '-'}",
                f"- ciphers ({len(ssh.ciphers)}): {', '.join(ssh.ciphers) or '-'}",
                f"- macs: {', '.join(ssh.macs) or '-'}",
                f"- host keys: {', '.join(ssh.host_key_algorithms) or '-'}",
                "",
            ]
    return _write(Path(report.artifacts[0].path).parent / "02-ciphers.md", "\n".join(lines))


def _orient_session(a: str, ap: int, b: str, bp: int) -> tuple[str, int, str, int]:
    server_ports = {21, 22, 25, 80, 110, 143, 389, 443, 465, 587, 636, 993, 995, 5061}
    if bp in server_ports or ap not in server_ports:
        return a, ap, b, bp
    return b, bp, a, ap


def _pfs(session: TlsSession) -> str:
    if session.forward_secrecy is True:
        return "yes"
    if session.forward_secrecy is False:
        return "**no**"
    return f"unknown ({session.forward_secrecy_reason or 'n/a'})"


def _cert_line(session: TlsSession) -> str:
    if not session.certs:
        return "not presented"
    leaf = session.certs[0]
    return f"{', '.join(leaf.common_names) or 'n/a'} (chain {len(session.certs)})"


# ---------------------------------------------------------------- findings
def render_findings(report: Report, index: CaptureIndex) -> Path:
    findings = _sorted_findings(report.findings)
    lines = [
        f"# 03 -- Findings in {report.capture.name}",
        "",
        f"{len(findings)} finding(s) from {len(report.detector_versions)} detector(s).",
        "",
        "Severity is this project's policy (see `docs/severity-model.md`); `confidence` says how sure we "
        "are from the capture alone. A high-severity/low-confidence item is a lead, not a conclusion.",
        "",
        "## Triage table",
        "",
    ]
    lines.append(
        _table(
            ["#", "Severity", "Confidence", "Code", "Title", "Detector"],
            [
                [str(i), SEVERITY_BADGE.get(f.severity, f.severity), f.confidence, f.code, f.title, f.detector]
                for i, f in enumerate(findings, 1)
            ],
        )
    )
    lines.append("## Detail")
    lines.append("")
    for i, finding in enumerate(findings, 1):
        lines += [
            f"<a id=\"{_anchor(finding)}\"></a>",
            f"### {i}. {finding.title}",
            "",
            f"- **Severity**: {SEVERITY_BADGE.get(finding.severity, finding.severity)}",
            f"- **Confidence**: {finding.confidence}",
            f"- **Code**: `{finding.detector}.{finding.code}`",
            f"- **Category**: {finding.category}",
        ]
        if finding.flow_key:
            lines.append(f"- **Flow**: `{finding.flow_key}`")
        if finding.subjects:
            lines.append(f"- **Subjects**: {', '.join(f'`{s}`' for s in finding.subjects[:8])}")
        lines += ["", _capture_text(finding.summary), ""]
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            lines.append(
                _table(
                    ["Frame", "Field", "Value"],
                    [[str(e.frame), f"`{_capture_text(e.field)}`", f"`{_capture_text(e.value)}`"]
                     for e in finding.evidence],
                )
            )
        if finding.remediation:
            lines += ["**Remediation**", "", finding.remediation, ""]
        if finding.references:
            lines.append(f"_References: {', '.join(finding.references)}_")
        if finding.tags:
            lines.append(f"_Tags: {' '.join(f'#{t}' for t in finding.tags)}_")
        lines.append("")
    if not findings:
        lines += [
            "_Nothing was raised. Reminder: absence of findings means the capture contains no evidence that "
            "tripped the detectors -- it does not mean the network is secure. Add captures at other points, "
            "and read the notes in `index.md`._",
            "",
        ]
    return _write(Path(report.artifacts[0].path).parent / "03-findings.md", "\n".join(lines))


def _mermaid_id(text: str) -> str:
    """A Mermaid-safe identifier derived from an address."""
    return "".join(ch if ch.isalnum() else "_" for ch in text)


def _anchor(finding: Finding) -> str:
    base = f"{finding.detector}-{finding.code}".lower().replace(".", "-")
    return f"{base}-{finding.id[:8]}".replace("_", "-")


# ---------------------------------------------------------------- diagrams
def render_diagrams(report: Report, index: CaptureIndex) -> Path:
    lines = [
        f"# 04 -- Diagrams for {report.capture.name}",
        "",
        "Mermaid sources render on GitHub, in VS Code (Markdown Preview Mermaid) and in mkdocs.",
        "",
        "## Topology -- who talks to whom",
        "",
        "Arrow weight is direction of the first packet; labels show bytes in the labelled direction. "
        "Thick arrows (`==>`) are encrypted, thin (`-->`) are cleartext.",
        "",
        mermaid.topology(index.flows),
        "",
        "## Crypto matrix -- client -> responder",
        "",
        mermaid.cipher_matrix(list(index.tls.values())),
        "",
        "## Findings by severity",
        "",
        mermaid.severity_pie(report.findings),
        "",
        "## Findings per detector",
        "",
        mermaid.detector_bars(report.findings),
        "",
        "## Media timeline (RTP)",
        "",
        mermaid.media_timeline(index.rtp),
        "",
        "## SIP call graph",
        "",
        _sip_graph(index),
        "",
    ]
    return _write(Path(report.artifacts[0].path).parent / "04-diagrams.md", "\n".join(lines))


def _sip_graph(index: CaptureIndex) -> str:
    """One sequence diagram per call, with the caller identified from the first request."""
    calls: dict[str, list[SipMessage]] = {}
    for msg in index.sip:
        calls.setdefault(msg.call_id or f"flow:{msg.key}", []).append(msg)
    if not calls:
        return "```mermaid\ngraph LR\n  empty[no SIP messages detected]\n```"
    lines = ["```mermaid", "sequenceDiagram"]
    declared: set[str] = set()
    shown = 0
    for call_id, messages in calls.items():
        if shown >= 6:
            break
        first = messages[0]
        flow = index.flows.get(first.key)
        if flow is None:
            continue
        shown += 1
        messages = sorted(messages, key=lambda m: m.frame)
        # Whoever sent the first request is the caller; everything else is a response.
        caller = _caller_of(first, flow)
        _p, a, ap, b, bp = endpoints_of(first.key)
        endpoints = {(a, ap): "caller", (b, bp): "callee"}
        for host, port in ((a, ap), (b, bp)):
            alias = "p" + _mermaid_id(host)
            if alias not in declared:
                declared.add(alias)
                lines.append(f"  participant {alias} as {host}:{port}")
        for msg in messages[:12]:
            label = msg.method or f"{msg.status} {msg.reason or ''}".strip()
            role = endpoints.get((_msg_host(msg, flow), _msg_port(msg, flow)), "caller")
            if msg.kind == "request" and role == "caller":
                lines.append(f"  {_alias(a, ap)}->>{_alias(b, bp)}: {label}")
            elif msg.kind == "request":
                lines.append(f"  {_alias(b, bp)}->>{_alias(a, ap)}: {label}")
            else:
                lines.append(f"  {_alias(b, bp)}-->>{_alias(a, ap)}: {label}")
        _ = caller
        _ = call_id
    lines.append("```")
    return "\n".join(lines)


def _caller_of(msg: SipMessage, flow: Flow) -> str:
    """The endpoint that sent the first request: a low port, else endpoint a."""
    if flow.port_a in {5060, 5061} or flow.port_b not in {5060, 5061}:
        return flow.endpoint_a
    return flow.endpoint_b


def _msg_host(msg: SipMessage, flow: Flow) -> str:
    return flow.endpoint_b if msg.port_hint == flow.port_b else flow.endpoint_a


def _msg_port(msg: SipMessage, flow: Flow) -> int:
    return msg.port_hint or flow.port_a


def _alias(host: str, port: int) -> str:
    return "p" + _mermaid_id(host)


# -------------------------------------------------------------------- json
def render_json(report: Report, path: Path) -> Path:
    """Machine-readable twin of the four artifacts."""
    path.write_text(json.dumps(report.to_json_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path
