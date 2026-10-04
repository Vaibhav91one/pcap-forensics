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
| `low` | Weak hints and context a reviewer should see. | truncated handshake, non-fatal TLS alert |
| `info` | Inventory and clustering that is not a defect on its own. | JA3 fleet, QUIC payload opacity, media volume anomaly, legacy record-layer version on a handshake record |

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
| `TLS_LEGACY_RECORD_VERSION` on a ClientHello | info | medium | The record-layer version is a protocol constant there, and the capture cannot say which record carried it (#150) |

## Protocol constants are inventory, not findings (#150)

A value the protocol *mandates* is not an observation about the traffic. A finding resting on one
still takes a line in the triage table, and an analyst reading top to bottom pays for it every time.

``TLS_LEGACY_RECORD_VERSION`` is the worked case. It reads ``tls.record.version``, and every conforming
modern client puts ``0x0301`` in the record layer of a ClientHello: RFC 8446 has a TLS 1.3 ClientHello
do exactly that and then states the field MUST be ignored in favour of ``supported_versions``, and
RFC 5246 does the same for the first record of a TLS 1.2 ClientHello. tshark's own expert info on
such a frame says the same thing.

Across the 219-capture corpus that code fired **26 times in 17 captures** — the most common code
in the corpus — and ``tshark`` puts every one of those values on a ClientHello and nowhere else.

**Decision: ``info`` severity, ``medium`` confidence, and the finding keeps firing.**

* **``info``, not ``low``.** ``low`` is defined above as context a reviewer should see. Here the
  reviewer sees it on every capture, because it is expected. Review question 1 — *if I am wrong
  about this, what actually happens?* — answers "nothing", and so does the value's own rule doc.
* **``medium``, not ``high``.** The capture cannot show *which* record carried the value.
  ``TlsSession.record_versions`` is a de-duplicated list of version names: no frame number, no record
  content type. Calling it ``high`` meant claiming certainty about a record the index never looked at,
  which AGENTS.md §4 forbids.
* **It still fires.** The one case that matters — a legacy version on a post-handshake application
  record, where a peer that honours the field would downgrade — is indistinguishable from the
  sentinel from the index alone. Suppressing the finding would discard the genuine case with the
  noise, and AGENTS.md §4 forbids trading a finding away for quiet.

### What this decision deliberately does not do

It does not suppress, so the corpus count stays at 26. That is the honest number, not an oversight:
the post-handshake rule in the rule doc is not implementable until ``TlsSession`` records a version per
record rather than per session. That is a schema change, core-owned, filed as
[#157](https://github.com/Vaibhav91one/pcap-forensics/issues/157).

It also does not fire only when ``supported_versions`` is absent. That field is empty on every TLS 1.2
ClientHello for protocol reasons, so the rule would keep most of the 26 while dropping nothing
real — verified against ``ws-tls12-chacha20poly1305.pcap``, where the sessions are ordinary TLS 1.2 with
no ``supported_versions`` at all.

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