# Writing a detector

A detector is one file, one pure function, and a claim it can defend with frames.

## The shape

```python
from typing import ClassVar

from ..index import CaptureIndex
from ..models import Finding
from .base import Detector, ev


class MyDetector(Detector):
    name: ClassVar[str] = "d5.my_check"     # id used by --only and in Finding.id
    title: ClassVar[str] = "One line a human can read"
    version: ClassVar[str] = "1"
    category: ClassVar[str] = "crypto"      # crypto | cleartext | voice | protocol | network
    description: ClassVar[str] = "What it detects and why it matters."
    enabled: ClassVar[bool] = True           # False until it produces a finding on a fixture

    def detect(self, index: CaptureIndex) -> list[Finding]:
        findings: list[Finding] = []
        for flow in index.flows.values():
            if not interesting(flow):
                continue
            findings.append(
                self.finding(
                    code="MY_CHECK_001",               # SCREAMING_SNAKE, stable forever
                    title=f"...",
                    severity="high",                    # impact if true
                    confidence="high",                  # certainty from the capture alone
                    summary="... state the fact, then the consequence.",
                    scope=flow.key,                     # unique per unit -> stable Finding.id
                    flow_key=flow.key,
                    subjects=[flow.endpoint_a, flow.endpoint_b],
                    evidence=[ev(flow.stream_index or 0, "tcp.port", flow.port_a)],
                    remediation="... the specific next action.",
                    references=["RFC 8996", "CWE-319"],
                    tags=["my-check"],
                )
            )
        return findings
```

`registry.py` picks it up automatically. There is no list to edit, which is what lets four agents
add detectors in parallel without merge conflicts.

## Rules that are not negotiable

**Pure.** No I/O, no network, no mutation of the index (use `index.note(...)` if you need to
record something for the report), no global state. The same capture must produce the same findings
on a different machine.

**Deterministic ids.** `Finding.id` is `detector.code.sha256(scope)[:16]`. `scope` must identify
the *unit* — the flow, the host, the certificate — and nothing that varies run to run. Never put a
timestamp, a packet count, or an iteration index in `scope`.

**Evidence or it did not happen.** Every finding needs at least one `Evidence(frame, field, value)`
with `frame > 0` and a non-empty value. If you cannot point at a frame, you do not have a finding;
you have a guess.

**Remediation is part of the finding.** "Upgrade TLS" is not a remediation. "Disable
`TLS_RSA_WITH_AES_128_CBC_SHA` in the server's cipher list and require ECDHE or TLS 1.3" is.

**Unknown means unknown.** If the value you need is `None`, either do not make the claim, or make
it with `confidence="low"` and say what is missing. `index.tls[key].forward_secrecy` is a tri-state
(`True`/`False`/`None` + a reason) precisely so you cannot accidentally turn "we could not tell"
into "no".

## What the index gives you

```python
index.capture                 # CaptureInfo: path, sha256, packets, bytes, window, tshark version
index.flows                   # dict[str, Flow] keyed by direction-independent flow key
index.hosts                   # dict[str, Host] with per-host flow/byte totals and roles
index.tls                     # dict[str, TlsSession] — hello details, suites, PFS, certs, alerts
index.http                    # list[HttpExchange] — method, host, status, redacted auth, cookies
index.dns                     # list[DnsQuery] — name, qtype, answers, is_response, over_tls
index.sip                     # list[SipMessage] — method/status, call id, SDP media + crypto
index.rtp                     # list[RtpStream] — ssrc, payload type, packets, bytes, duration
index.ssh                     # list[SshSession] — versions and negotiated algorithms
index.quic                    # list[QuicSession] — versions, SNI, inner TLS versions
index.services                # list[ServiceHit] — other protocols we recognise but do not model
index.notes                   # list[str] — add here when the capture surprised you
```

Helpers worth knowing:

```python
index.flow(key)                       # Flow | None
index.flow_by("10.0.0.5", 443)        # Flow | None
index.flows_touching("10.0.0.5")       # every conversation an IP took part in
index.flows_with_app("tls", "quic")    # by application protocol
index.mark_encrypted(key, "why")       # only for core use; detectors read, they do not write
```

If you need something that is not there, it goes in an issue against `models.py`/`index.py`.
That is deliberate friction: it keeps the four detectors speaking one schema.

## Crypto reasoning

Never re-derive cipher weakness. Use the registry:

```python
from ..data_ciphers import lookup, name_of, weakness_reasons, forward_secrecy_for, is_deprecated_version

suite = lookup(session.chosen_cipher)   # CipherSuite | None
suite.deprecation                       # prohibited | deprecated | legacy | acceptable | recommended | signalling
suite.forward_secrecy                   # bool
", ".join(weakness_reasons(session.chosen_cipher))
is_deprecated_version("TLS 1.0")        # True
```

If `lookup` returns `None`, that is a registry gap, not a pass. Raise a finding or a note.

## Testing

Two halves, and you need both.

```python
# 1. a synthetic fixture that must trigger exactly your codes
def test_my_detector(analyze_capture):
    result = analyze_capture(fixture("my_case.pcap"))
    assert "MY_CHECK_001" in codes(result)

# 2. a negative case: a fixture that must stay quiet
def test_my_detector_is_quiet_on_modern_tls(analyze_capture):
    result = analyze_capture(fixture("strong_tls13.pcap"))
    assert "MY_CHECK_001" not in codes(result)
```

The negative case is the one that keeps the tool honest. Write it before you write the positive
one if you can.

Generate fixtures in `scripts/make_fixtures.py`:

* plain byte fixtures (HTTP, DNS, SIP, RTP, scan shapes) are written directly with `struct`,
* TLS handshakes are **captured**, never hand-rolled — see `_tls_through_proxy`, which performs a
  real OpenSSL handshake and splices the wire bytes into a pcap.

Assert on codes, never on prose. Wording is not behaviour, and a rewording should not turn CI red.

## Before you open the PR

```bash
make verify
pf doctor
pf analyze tests/fixtures/my_case.pcap -o /tmp/x   # read your own report
```

Then read your own `03-findings.md` as if you were the analyst receiving it at 2am. If you would
not act on it, fix it before submitting.
