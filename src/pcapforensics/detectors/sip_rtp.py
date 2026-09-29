"""D3 -- SIP signalling and RTP media security.

Builds the call graph, then answers the question that matters for voice/video:
was the media encrypted (SRTP) or did it go out in the clear, and did the
signalling itself leak credentials?
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding, RtpStream, SipMessage
from .base import Detector, ev

#: tshark's ``sdp.media`` field value is the media line body, e.g.
#: ``audio 20000 RTP/AVP 8 0 101`` -- the leading "m=" is already stripped.
MEDIA_RE = re.compile(r"^(audio|video)\b", re.IGNORECASE)
#: The crypto suite token tshark exposes for ``a=crypto:`` lines.
CRYPTO_ATTR_RE = re.compile(r"(AES_CM_\d+_HMAC_SHA1_\d+|AES_GCM|AES_CCM|F8|AEAD_AES_\d+_GCM)", re.IGNORECASE)
SRTP_MODES = {"aes_cm_128", "aes_256_cm", "aes_gcm", "aes_gcm_8", "f8", "cm_hmac"}


class SipRtpDetector(Detector):
    name: ClassVar[str] = "d3.sip_rtp"
    title: ClassVar[str] = "SIP signalling and RTP media exposure"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "voice"
    description: ClassVar[str] = (
        "Reconstructs SIP call flows, flags cleartext REGISTER/INVITE credentials, and "
        "detects RTP media sent without SRTP protection."
    )

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        calls = self._group_calls(index)
        findings += self._cleartext_signalling(index)
        findings += self._sdp_without_crypto(index, calls)
        findings += self._rtp_unprotected(index, calls)
        findings += self._rtp_volume(index)
        return findings

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _group_calls(index: CaptureIndex) -> dict[str, list[SipMessage]]:
        calls: dict[str, list[SipMessage]] = defaultdict(list)
        for msg in index.sip:
            calls[msg.call_id or f"flow:{msg.key}"].append(msg)
        for messages in calls.values():
            messages.sort(key=lambda m: m.frame)
        return calls

    def _rtp_streams_for(self, index: CaptureIndex, call_ids: set[str]) -> list[RtpStream]:
        if not call_ids:
            return []
        ports: set[int] = set()
        for msg in index.sip:
            if (msg.call_id or "") in call_ids:
                ports.update(p for p in (self._ports_of(index, msg.key)) if p > 1024)
        return [s for s in index.rtp if s.key in {r.key for r in index.rtp} and self._has_port(index, s, ports)]

    @staticmethod
    def _ports_of(index: CaptureIndex, key: str) -> list[int]:
        from ..models import endpoints_of

        _proto, _a, ap, _b, bp = endpoints_of(key)
        return [ap, bp]

    @staticmethod
    def _has_port(index: CaptureIndex, stream: RtpStream, ports: set[int]) -> bool:
        from ..models import endpoints_of

        _proto, _a, ap, _b, bp = endpoints_of(stream.key)
        return bool({ap, bp} & ports)

    # -- checks -------------------------------------------------------------
    def _cleartext_signalling(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        by_key: dict[str, list[SipMessage]] = defaultdict(list)
        for msg in index.sip:
            if not msg.via_encrypted_transport:
                by_key[msg.key].append(msg)
        for key, messages in by_key.items():
            flow = index.flows.get(key)
            if flow is None:
                continue
            methods = sorted({m.method for m in messages if m.method})
            auth = [m for m in messages if m.has_auth_header]
            agents = sorted({m.user_agent for m in messages if m.user_agent})
            if not messages:
                continue
            severity = "high" if auth else "medium"
            summary = (
                f"{len(messages)} SIP message(s) travelled in cleartext between "
                f"{flow.endpoint_a}:{flow.port_a} and {flow.endpoint_b}:{flow.port_b}"
                + (f": {', '.join(methods)}" if methods else "")
                + (f". Authentication headers present on {len(auth)} message(s): credentials are "
                   "hash/challenge based but still replayable by anyone on-path." if auth else ".")
                + (f" User-Agent: {', '.join(agents)}." if agents else "")
            )
            out.append(
                self.finding(
                    code="SIP_CLEARTEXT_SIGNALLING",
                    title=f"SIP in cleartext on {key}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    summary=summary,
                    scope=f"{key}|sig",
                    flow_key=key,
                    subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[
                        ev(m.frame, "sip.Method", m.method or f"status {m.status}") for m in messages[:4]
                    ]
                    + [ev(auth[0].frame, "sip.authentication_scheme", auth[0].auth_scheme) for _ in auth[:1]],
                    remediation="Move to SIP over TLS (port 5061) or at minimum use TLS for the signalling leg.",
                    references=["RFC 3261", "RFC 7115", "CWE-319"],
                    tags=["sip", "cleartext"],
                )
            )
        return out

    def _sdp_without_crypto(self, index: CaptureIndex, calls: dict[str, list[SipMessage]]) -> list[Finding]:
        out: list[Finding] = []
        for call_id, messages in calls.items():
            for msg in messages:
                if not msg.sdp_media:
                    continue
                if any(CRYPTO_ATTR_RE.search(line) for line in msg.sdp_crypto_lines):
                    continue
                kinds = []
                for line in msg.sdp_media:
                    match = MEDIA_RE.match(line.strip())
                    kinds.append(match.group(1).lower() if match else "?")
                if not any(k in {"audio", "video"} for k in kinds):
                    continue
                out.append(
                    self.finding(
                        code="SDP_NO_CRYPTO_ATTR",
                        title=f"Offered media without SRTP crypto attribute (call {call_id})",
                        severity="high",
                        confidence="high",
                        summary=(
                            f"SDP in frame {msg.frame} advertises {', '.join(kinds)} media with no a=crypto "
                            "line, so RFC 4568 SRTP cannot be negotiated. If RTP then flows, the call is "
                            "eavesdroppable in cleartext."
                        ),
                        scope=f"{msg.key}|sdp|{msg.frame}",
                        flow_key=msg.key,
                        subjects=[u for u in (msg.from_user, msg.to_user) if u],
                        evidence=[ev(msg.frame, "sdp.media_desc", "; ".join(msg.sdp_media)[:160])],
                        remediation="Advertise SDES-SRTP (a=crypto) or DTLS-SRTP in every SDP offer.",
                        references=["RFC 4568", "RFC 5764"],
                        tags=["sip", "rtp", "srtp"],
                    )
                )
        return out

    def _rtp_unprotected(self, index: CaptureIndex, calls: dict[str, list[SipMessage]]) -> list[Finding]:
        out: list[Finding] = []
        for stream in index.rtp:
            call_ids = {m.call_id for m in index.sip if m.key == stream.key and m.call_id}
            media = [m for m in index.sip if m.key == stream.key and m.sdp_media]
            protected = any(CRYPTO_ATTR_RE.search(line) for m in media for line in m.sdp_crypto_lines)
            if protected:
                continue
            minutes = stream.duration / 60
            severity = "high" if stream.bytes > 20_000 or minutes > 1 else "medium"
            out.append(
                self.finding(
                    code="RTP_MEDIA_UNPROTECTED",
                    title=f"RTP media in cleartext on {stream.key}",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high" if not media else "medium",
                    summary=(
                        f"{stream.packets} RTP packets ({stream.bytes} bytes, {stream.duration:.1f}s) flowed "
                        f"{stream.from_ip} -> {stream.to_ip} on payload type "
                        f"{stream.payload_type} ({stream.payload_name or 'unknown'}) with no SRTP protection "
                        "negotiated. Voice and video content is directly recoverable."
                    ),
                    scope=f"{stream.key}|rtp|{stream.ssrc}",
                    flow_key=stream.key,
                    subjects=[x for x in (stream.from_ip, stream.to_ip) if x],
                    evidence=[
                        ev(stream.first_frame, "rtp.ssrc", stream.ssrc),
                        ev(stream.first_frame, "rtp.p_type", f"{stream.payload_type} {stream.payload_name or ''}".strip()),
                    ],
                    remediation="Require SRTP (SDES or DTLS-SRTP) for all media; consider SIP-TLS signalling too.",
                    references=["RFC 3711", "RFC 4568"],
                    tags=["rtp", "cleartext"],
                )
            )
            _ = call_ids
        return out

    def _rtp_volume(self, index: CaptureIndex) -> list[Finding]:
        out: list[Finding] = []
        total = sum(s.bytes for s in index.rtp)
        for stream in index.rtp:
            if total < 50_000 or stream.bytes / total < 0.5:
                continue
            out.append(
                self.finding(
                    code="RTP_VOLUME_ANOMALY",
                    title=f"{stream.bytes / total:.0%} of RTP volume on one stream ({stream.key})",
                    severity="info",
                    confidence="low",
                    summary=(
                        f"SSRC {stream.ssrc} carries {stream.bytes / 1024:.0f} KiB of the {total / 1024:.0f} KiB "
                        f"observed RTP, which may be a long call, a loopback, or duplicated capture interface."
                    ),
                    scope=f"{stream.key}|volume",
                    flow_key=stream.key,
                    subjects=[x for x in (stream.from_ip, stream.to_ip) if x],
                    evidence=[ev(stream.first_frame, "rtp.ssrc", stream.ssrc)],
                    remediation="No action unless unexpected; confirm the capture point did not duplicate traffic.",
                    references=[],
                    tags=["rtp"],
                )
            )
        return out


def crypto_modes(sdp_crypto_lines: list[str]) -> set[str]:
    """SDES-SRTP suite tokens found in the SDP, e.g. ``AES_CM_128_HMAC_SHA1_80``."""
    modes: set[str] = set()
    for line in sdp_crypto_lines:
        match = CRYPTO_ATTR_RE.search(line)
        if match:
            modes.add(match.group(0).upper())
    return modes
