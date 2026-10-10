"""Suricata EVE-compatible JSON events for SIEM ingest: alert, flow, dns, http, tls, fileinfo (issue #200).

Built from the Zeek-style log tables (``logs.py``), so both outputs always agree. One JSON object per event,
ordered by time. Field names follow Suricata's EVE schema; where a value is not known it is left out.

* ``alert``: one per pcap-doctor finding. ``signature_id`` is derived from the finding code (stable, in the
  range 9000000-9999999, away from the ET/Snort ranges); ``severity`` is 1 for critical/high, 2 medium, 3 low/info.
* ``flow_id`` is a stable integer derived from the flow key.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from .index import CaptureIndex
from .logs import build_logs

EVENT_TYPES = ("alert", "flow", "dns", "http", "tls", "fileinfo")
_SEVERITY = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 3}


def signature_id(code: str) -> int:
    return 9_000_000 + int(hashlib.sha256(code.encode()).hexdigest()[:8], 16) % 1_000_000


def _flow_id(uid: str | None) -> int | None:
    return int(uid[1:16], 16) if uid else None


def _stamp(ts: float | None, fallback: float) -> str:
    return datetime.fromtimestamp(ts if ts is not None else fallback, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _base(row: dict[str, Any], event_type: str, fallback: float, proto: str | None = None) -> dict[str, Any]:
    event: dict[str, Any] = {"timestamp": _stamp(row.get("ts"), fallback)}
    if row.get("uid"):
        event["flow_id"] = _flow_id(row["uid"])
    event["event_type"] = event_type
    if row.get("id.orig_h"):
        event.update(src_ip=row["id.orig_h"], src_port=row["id.orig_p"], dest_ip=row["id.resp_h"], dest_port=row["id.resp_p"])
    if proto:
        event["proto"] = proto.upper()
    return event


def build_eve(index: CaptureIndex, types: tuple[str, ...] = EVENT_TYPES) -> list[dict[str, Any]]:
    unknown = [t for t in types if t not in EVENT_TYPES]
    if unknown:
        raise ValueError(f"unknown event type(s) {', '.join(unknown)}; types: {', '.join(EVENT_TYPES)}")
    t = build_logs(index, ("conn", "dns", "http", "ssl", "x509", "files", "notice"))
    fallback = index.capture.first_seen
    protos = {r["uid"]: r["proto"] for r in t["conn"].rows}
    events: list[dict[str, Any]] = []

    if "flow" in types:
        for r in t["conn"].rows:
            end = r["ts"] + (r["duration"] or 0.0)
            ev = _base(r, "flow", fallback, r["proto"])
            ev["app_proto"] = r["service"] or "failed"
            ev["flow"] = {
                "pkts_toserver": r["orig_pkts"], "pkts_toclient": r["resp_pkts"],
                "bytes_toserver": r["orig_ip_bytes"], "bytes_toclient": r["resp_ip_bytes"],
                "start": _stamp(r["ts"], fallback), "end": _stamp(end, fallback), "age": int(r["duration"] or 0),
                "state": {"SF": "closed", "S1": "established", "S0": "new"}.get(r["conn_state"], "closed"),
                "reason": "timeout" if r["conn_state"] in ("S1", "S0") else "shutdown",
                "conn_state": r["conn_state"],
            }
            events.append(ev)
    if "dns" in types:
        for n, r in enumerate(t["dns"].rows):
            ev = _base(r, "dns", fallback, r["proto"])
            ev["app_proto"] = "dns"
            query = {"type": "query", "id": n, "rrname": r["query"], "rrtype": r["qtype_name"]}
            events.append({**ev, "dns": query})
            if r.get("rcode_name") is not None:
                answer: dict[str, Any] = {"version": 2, "type": "answer", "id": n, "rrname": r["query"],
                                          "rrtype": r["qtype_name"], "rcode": r["rcode_name"]}
                if r.get("answers"):
                    answer["answers"] = [{"rrname": r["query"], "rrtype": r["qtype_name"], "rdata": a} for a in r["answers"]]
                events.append({**ev, "dns": answer})
    if "http" in types:
        for r in t["http"].rows:
            ev = _base(r, "http", fallback, protos.get(r["uid"], "tcp"))
            ev["app_proto"] = "http"
            http: dict[str, Any] = {"hostname": r["host"], "url": r["uri"], "http_user_agent": r["user_agent"],
                                    "http_method": r["method"], "protocol": r["version"], "status": r["status_code"],
                                    "http_content_type": (r["resp_mime_types"] or [None])[0]}
            ev["http"] = {k: v for k, v in http.items() if v is not None}
            events.append(ev)
    if "tls" in types:
        certs = {r["id"]: r for r in t["x509"].rows}
        for r in t["ssl"].rows:
            ev = _base(r, "tls", fallback, protos.get(r["uid"], "tcp"))
            ev["app_proto"] = "tls"
            tls: dict[str, Any] = {"version": r["version"], "sni": r["server_name"]}
            leaf = certs.get((r["cert_chain_fuids"] or [""])[0])
            if leaf:
                tls.update(subject=leaf["certificate.subject"], issuerdn=leaf["certificate.issuer"],
                           notbefore=leaf["certificate.not_valid_before"], notafter=leaf["certificate.not_valid_after"])
            if r["ja3"]:
                tls["ja3"] = {"hash": r["ja3"]}
            if r["ja3s"]:
                tls["ja3s"] = {"hash": r["ja3s"]}
            ev["tls"] = {k: v for k, v in tls.items() if v is not None}
            events.append(ev)
    if "fileinfo" in types:
        for r in t["files"].rows:
            uid = (r.get("conn_uids") or [None])[0]
            ev = _base({"ts": r.get("ts"), "uid": uid}, "fileinfo", fallback, protos.get(uid or "", "tcp"))
            ev["app_proto"] = (r["source"] or "").lower()
            info = {"filename": r["filename"], "magic": r["mime_type"], "state": "CLOSED", "stored": False}
            for key in ("md5", "sha1", "sha256"):
                if r.get(key) is not None:
                    info[key] = r[key]
            if r.get("seen_bytes") is not None:
                info["size"] = r["seen_bytes"]
            ev["fileinfo"] = {k: v for k, v in info.items() if v is not None}
            events.append(ev)
    if "alert" in types:
        for r in t["notice"].rows:
            ev = _base(r, "alert", fallback, protos.get(r.get("uid") or ""))
            ev["alert"] = {"action": "allowed", "gid": 1, "signature_id": signature_id(r["note"]), "rev": 1,
                           "signature": r["msg"], "category": r["note"], "severity": _SEVERITY.get(r["severity"], 3)}
            ev["metadata"] = {"summary": r["sub"]}
            events.append(ev)
    events.sort(key=lambda e: e["timestamp"])
    return events
