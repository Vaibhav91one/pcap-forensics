"""Mermaid diagram builders for the report artifacts.

Every builder is total: empty input produces an empty-but-valid diagram, never
an exception and never a half-rendered block.
"""

from __future__ import annotations

from collections import Counter

from ..data_ciphers import name_of
from ..models import Finding, Flow, RtpStream, TlsSession

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _label(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ")


def topology(index_flows: dict[str, Flow], limit: int = 24) -> str:
    """Who talks to whom. Server side first, clients on the outside."""
    flows = sorted(index_flows.values(), key=lambda f: (-f.bytes, f.key))[:limit]
    if not flows:
        return "```mermaid\ngraph LR\n  empty[no flows detected]\n```"
    lines = ["```mermaid", "graph LR"]
    ids: dict[tuple[str, int], str] = {}

    def node(ip: str, port: int) -> str:
        ident = ids.get((ip, port))
        if ident is None:
            ident = "n" + str(len(ids))
            ids[(ip, port)] = ident
        return ident

    edges: list[tuple[str, str, int, str, bool]] = []
    for flow in flows:
        server_is_a = flow.port_a in {80, 443, 22, 25, 389, 5060, 5061, 161, 123, 21, 23, 3306, 6379} or (
            flow.port_b not in {80, 443, 22, 25, 389, 5060, 5061, 161, 123, 21, 23, 3306, 6379}
        )
        srv = (flow.endpoint_a, flow.port_a) if server_is_a else (flow.endpoint_b, flow.port_b)
        cli = (flow.endpoint_b, flow.port_b) if server_is_a else (flow.endpoint_a, flow.port_a)
        edges.append((node(*srv), node(*cli), flow.bytes, flow.app_proto, bool(flow.encrypted)))
    for (ip, port), ident in ids.items():
        lines.append(f'  {ident}["{_label(ip)}:{port}"]')
    for src, dst, nbytes, app, enc in edges:
        arrow = "==>" if enc else "-->"
        lines.append(f'  {src} {arrow}|"{_label(app)} {nbytes}B"| {dst}')
    lines.append("```")
    return "\n".join(lines)


def cipher_matrix(sessions: list[TlsSession], limit: int = 20) -> str:
    """Sender -> recipient with the negotiated suite and version."""
    if not sessions:
        return "```mermaid\ngraph LR\n  empty[no TLS sessions detected]\n```"
    lines = ["```mermaid", "graph LR"]
    seen: dict[str, str] = {}

    def node(text: str) -> str:
        ident = seen.get(text)
        if ident is None:
            ident = "t" + str(len(seen))
            seen[text] = ident
        return ident

    for session in sessions[:limit]:
        _p, a, ap, b, bp = _endpoints(session.key)
        srv, cli = (a, ap), (b, bp)
        if bp < ap:
            srv, cli = (b, bp), (a, ap)
        src = node(f"{cli[0]}:{cli[1]}")
        dst = node(f"{srv[0]}:{srv[1]}")
        cipher = name_of(session.chosen_cipher)
        version = session.negotiated_version or (session.record_versions[0] if session.record_versions else "?")
        pfs = "PFS" if session.forward_secrecy else ("no-PFS" if session.forward_secrecy is False else "PFS?")
        sni = f" {session.sni}" if session.sni else ""
        lines.append(f'  {src} -->|"{_label(version)} / {cipher} / {pfs}{sni}"| {dst}')
    lines.append("```")
    return "\n".join(lines)


def severity_pie(findings: list[Finding]) -> str:
    counts: Counter[str] = Counter(f.severity for f in findings)
    if not counts:
        return "```mermaid\npie title Findings\n  \"none\" : 1\n```"
    lines = ["```mermaid", "pie title Findings by severity"]
    for severity in SEVERITY_ORDER:
        if counts.get(severity):
            lines.append(f'  "{severity}" : {counts[severity]}')
    lines.append("```")
    return "\n".join(lines)


def detector_bars(findings: list[Finding]) -> str:
    counts: Counter[str] = Counter(f.detector for f in findings)
    if not counts:
        return "_No findings._"
    lines = ["```mermaid", "xychart-beta", '  title "Findings per detector"', '  x-axis ["' + '", "'.join(sorted(counts)) + '"]', '  y-axis "count" 0 --> ' + str(max(counts.values()) + 1)]
    lines.append('  bar [' + ", ".join(str(counts[k]) for k in sorted(counts)) + "]")
    lines.append("```")
    return "\n".join(lines)


def media_timeline(streams: list[RtpStream], window: float = 30.0) -> str:
    if not streams:
        return "```mermaid\ngantt\n  title RTP media\n  no RTP streams detected :done\n```"
    base = min(s.first_seen for s in streams)
    lines = ["```mermaid", "gantt", "  title RTP media windows (30s buckets)"]
    for stream in sorted(streams, key=lambda s: s.first_seen)[:12]:
        start = max(0.0, (stream.first_seen - base) // window) * window
        end = max(start + window, ((stream.last_seen - base) // window + 1) * window)
        label = f"ssrc {stream.ssrc} {stream.bytes // 1024}KiB"
        lines.append(f"  {label} :a{str(int(start)).replace('.', '')}, {int(end - start)}s")
    lines.append("```")
    return "\n".join(lines)


def _endpoints(key: str) -> tuple[str, str, int, str, int]:
    from ..models import endpoints_of

    proto, a, ap, b, bp = endpoints_of(key)
    return proto, a, ap, b, bp


def _endpoints_tuple(key: str) -> tuple[str, str, int, str, int]:  # pragma: no cover
    return _endpoints(key)
