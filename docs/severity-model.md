# Severity model

Severity and confidence are two different questions and are scored independently. This document
is the policy the detectors implement; `AGENTS.md` §5 is the short version for contributors.

- **Severity** — how bad is this *if it is true*?
- **Confidence** — how sure are we *from this capture alone*?

A high-severity, low-confidence item is a lead. A low-severity, high-confidence item is a fact that
happens to be boring. Collapsing them into one number is how triage tools lose their user's trust.

## Severity tiers

| Tier | Definition | Typical examples |
|---|---|---|
| `critical` | Secret material or key material is exposed, or a prohibited cipher is negotiated. Compromise does not require another bug. | HTTP Basic/Digest over cleartext, SNMP community or Redis/MySQL credential in the clear, `NULL` cipher, export-grade suite, RC4, 3DES, single DES |
| `high` | Confidentiality of captured traffic is at risk without any further user action. | no forward secrecy, TLS 1.0/1.1, DTLS 1.0, cleartext SIP signalling, RTP without SRTP, expired certificate, weak certificate key |
| `medium` | Downgrade surface, policy violations, or strong heuristics. Real risk, but something stands between the finding and exploitation. | weak suites offered but not chosen, cookie without `Secure`, cleartext service, DNS tunnelling shape, service on an odd port, SYN-scan shape, self-signed leaf |
| `low` | Legacy fields, weak hints, context a reviewer should see. | legacy record-layer version, truncated handshake, non-fatal TLS alert |
| `info` | Inventory and clustering that is not a defect on its own. | JA3 fleet, QUIC payload opacity, media volume anomaly |

## Confidence tiers

| Tier | Meaning |
|---|---|
| `high` | The evidence is directly visible in the capture: a negotiated suite in a ServerHello, a credential in a packet payload, a certificate in a Certificate message. |
| `medium` | The evidence is present but needs one inference: a port heuristic, a chain of two fields, an SDP line that implies a media path. |
| `low` | A shape, not a fact: entropy and label-depth heuristics, inter-arrival regularity, a fingerprint cluster. Always name the false-positive sources in `summary`. |

## Worked examples

| Observation | Severity | Confidence | Why |
|---|---|---|---|
| `TLS_RSA_WITH_AES_128_CBC_SHA` negotiated | high | high | Directly in the ServerHello; static key exchange is visible from the suite name |
| Client also offers `0x000A` (3DES) on a TLS 1.3 session | medium | high | Directly in the ClientHello; downgrade surface, not a live weakness |
| RSA-AES128-SHA negotiated on TLS 1.2 | high | high | No PFS is a property of the suite, not a guess |
| 24 deeply-labelled, high-entropy TXT queries from one host | medium | low | Could be tunnelling, could be a CDN or service discovery; the summary says both |
| 39 unanswered SYNs from one IP to consecutive ports | medium | medium | Shape is clear; a permitted scanner produces the same thing |
| One JA3 fingerprint across 40 servers | info | medium | Fleet, or a scanner; inventory value only |
| `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` seen | (none) | — | Not a cipher; filtered out before a finding is considered |

## Things that are deliberately *not* findings

* Unknown SNI, unusual hostnames, high-traffic hosts, geo mismatch. No policy basis.
* "This looks like a scanner" without a shape (port progression, unanswered SYNs, uniform timing).
* A cipher we simply do not have in the registry, unless we report it as `TLS_CIPHER_UNKNOWN` — which
  is a registry gap, and a real one.
* TLS alerts without context. A `close_notify` is not a finding; a fatal alert repeated across hosts is.

## Review questions for a severity

1. If I am wrong about this, what actually happens? If the answer is "nothing", it is `info` or `low`.
2. Does the reader need to do something, or is something being done to them?
3. Would I escalate this at 2am? If yes, `high` or `critical`. If I would file a ticket, `medium`. If
   I would note it, `low`.
4. Is the confidence honest? If I would need a second capture to be sure, it is not `high`.
