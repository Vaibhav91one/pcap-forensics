# Seed issue board

Copy this into GitHub Issues (or keep it here as the backlog) at repository setup. Each item is
one issue, with the allowlist its agent gets. The order is a dependency order, not a priority order.

Labels: `core` · `detector/d1` · `detector/d2` · `detector/d3` · `detector/d4` · `artifact/*` ·
`oracle` · `good-first-issue` · `blocked`

---

## Phase 0 — core (R0, serial, blocks everything)

| # | Title | Allowlist | Done when |
|---|---|---|---|
| 1 | `core: frozen CaptureIndex contract` | `models.py`, `index.py` | every protocol a detector needs is projected; `schema_version` pinned |
| 2 | `core: tshark boundary with field-drift handling` | `tshark.py` | fields validated against `-G fields`; drops recorded as notes; prefs validated |
| 3 | `core: cipher registry derived from tshark` | `scripts/gen_cipher_suites.py`, `data/*` | 424 suites, names agreeing with `tshark -G values` |
| 4 | `core: certificate enrichment via openssl` | `certificates.py` | subject/issuer/key size/SANs exact, or a note explaining why not |
| 5 | `artifact: four numbered artifacts + index` | `render/*` | 6 files written, tables well-formed, mermaid balanced |
| 6 | `core: CLI, exit codes, cache` | `cli.py`, `pipeline.py` | `--fail-on` for CI, cache keyed by sha+version+args |
| 7 | `core: synthetic fixture generator` | `scripts/make_fixtures.py`, `tests/fixtures/*` | TLS fixtures captured from real handshakes, not hand-rolled bytes |
| 8 | `core: regression corpus` | `scripts/fetch_captures.sh`, `captures/`, `tests/test_corpus.py` | every assertion checked by hand against `tshark -V` |
| 9 | `core: CI` | `.github/workflows/ci.yml`, `Makefile` | `make verify` is the gate; fixture drift fails the build |

**Freeze gate:** after #1–#9 merge, `report.schema_version` is pinned and the four detector agents
start. Nothing below may edit the core.

## Phase 1 — detectors (R1–R4, parallel, isolated)

### R1 · `d1.tls_cipher` (`detector/d1`)

| # | Title | Fixture | Must raise |
|---|---|---|---|
| 10 | `detector: deprecated protocol version` | `weak_tls.pcap` | `TLS_VERSION_DEPRECATED` |
| 11 | `detector: weak or prohibited chosen suite` | `weak_tls.pcap` | `TLS_CIPHER_WEAK` |
| 12 | `detector: no forward secrecy` | `no_pfs_tls12.pcap` | `TLS_NO_FORWARD_SECRECY` |
| 13 | `detector: offered-but-unused weak suites` | `mixed_ciphers.pcap` | `TLS_OFFERS_WEAK_CIPHERS` (and **not** `TLS_CIPHER_WEAK`) |
| 14 | `detector: certificate expiry, key size, signature algorithm` | captured expired/weak cert | `TLS_CERT_EXPIRED`, `TLS_CERT_WEAK_KEY`, `TLS_CERT_WEAK_SIGALG` |
| 15 | `detector: self-signed leaf` | `no_pfs_tls12.pcap` | `TLS_SELF_SIGNED_CHAIN` |
| 16 | `detector: DTLS coverage and DTLS 1.0` | `snakeoil-dtls.pcap` | version + suite findings on UDP |
| 17 | `detector: TLS alerts and truncated handshakes` | scan-style capture | `TLS_FATAL_ALERT`, `TLS_HANDSHAKE_TRUNCATED` |
| 18 | `detector: JA3 fleet clustering` | generated multi-host capture | `TLS_JA3_FLEET` at `info` |

### R2 · `d2.transport_exposure` (`detector/d2`)

| # | Title | Fixture | Must raise |
|---|---|---|---|
| 19 | `detector: HTTP auth in cleartext` | `http_basic.pcap` | `HTTP_CLEARTEXT_AUTH` |
| 20 | `detector: Basic auth inside TLS` | TLS-wrapped Basic | `HTTP_BASIC_AUTH` (low) |
| 21 | `detector: cookies without Secure` | `http_basic.pcap` | `HTTP_COOKIE_NO_SECURE` |
| 22 | `detector: cleartext services (FTP/Telnet/NTP/TFTP/…)` | per-protocol fixtures | `CLEARTEXT_SERVICE` |
| 23 | `detector: credentials in cleartext (SNMP/LDAP/Redis/MySQL)` | each protocol | `CLEARTEXT_CREDENTIAL`, redacted |
| 24 | `detector: service on a non-standard port` | `tftp.pcap` | `SERVICE_ON_ODD_PORT` |
| 25 | `detector: unanswered-SYN scan shape` | `syn_scan.pcap` | `SYN_SCAN_SHAPE` |
| 26 | `detector: beaconing shape` | generated regular-interval capture | `BEACONING_SHAPE` at low confidence |
| 27 | `detector: redaction regression guard` | `http_basic.pcap` | test greps artifacts for the secret |

### R3 · `d3.sip_rtp` (`detector/d3`)

| # | Title | Fixture | Must raise |
|---|---|---|---|
| 28 | `detector: SIP call graph` | `sip-rtp.pcapng` | sequence diagram with call legs |
| 29 | `detector: cleartext SIP signalling with auth headers` | `sip_rtp.pcap` | `SIP_CLEARTEXT_SIGNALLING` |
| 30 | `detector: SDP without an a=crypto attribute` | `sip_rtp.pcap` | `SDP_NO_CRYPTO_ATTR` |
| 31 | `detector: RTP media without SRTP` | `sip_rtp.pcap` | `RTP_MEDIA_UNPROTECTED` |
| 32 | `detector: RTP on dynamic ports (SDP-driven decode-as)` | port 20000 fixture | the RTP stream is found at all |
| 33 | `detector: media volume anomaly` | `sip-rtp.pcapng` | `RTP_VOLUME_ANOMALY` |
| 34 | `detector: SIP digest response never echoed` | `sip_rtp.pcap` | test greps artifacts for the nonce/response |

### R4 · `d4.dns_quic_ssh` (`detector/d4`)

| # | Title | Fixture | Must raise |
|---|---|---|---|
| 35 | `detector: plaintext DNS leakage` | `dns_port.pcap` | `DNS_CLEARTEXT` |
| 36 | `detector: DNS tunnelling shape` | `dns_tunnel.pcap` | `DNS_TUNNEL_SHAPE` at low/medium confidence |
| 37 | `detector: external resolver in use` | capture with public resolver | `DNS_EXTERNAL_RESOLVER` |
| 38 | `detector: QUIC inventory and payload opacity` | `quic-with-secrets.pcapng` | `QUIC_PAYLOAD_OPAQUE` + SNI note |
| 39 | `detector: QUIC with a keylog (inner HTTP/3)` | capture + `SSLKEYLOGFILE` | payload visible; `QUIC_PAYLOAD_OPAQUE` absent |
| 40 | `detector: weak SSH algorithm negotiation` | generated SSH fixture | `SSH_WEAK_KEX`, `SSH_WEAK_CIPHER`, `SSH_WEAK_MAC`, `SSH_WEAK_HOSTKEY` |
| 41 | `detector: DoH/DoT-aware DNS classification` | DNS-over-TLS fixture | no `DNS_CLEARTEXT` for encrypted DNS |

## Phase 1 — cross-cutting (R5 qa, parallel with the detectors)

| # | Title | Allowlist | Done when |
|---|---|---|---|
| 42 | `oracle: cross-check D1 against netsniff-ng tlsaudit` | `tests/test_oracle.py` | non-blocking job, disagreements filed as issues |
| 43 | `qa: read 03-findings.md end to end for each corpus capture` | issues only | every finding an analyst would act on; the rest fixed or downgraded |
| 44 | `artifact: report.json schema documentation` | `docs/`, `report.json` consumers | every field documented; versioning policy written |
| 45 | `artifact: severity histogram by host in index.md` | `render/markdown.py` | top offenders visible without opening findings |

## Phase 2 — optional integrations

| # | Title | Notes |
|---|---|---|
| 46 | `integration: skydive topology export` | borrow the flow-graph model for the topology diagram; optional live topology later |
| 47 | `integration: homer/SIP call export` | emit our call graph in a format Homer can ingest |
| 48 | `integration: pyshark adapter for notebooks` | behind the same source interface; never on the critical path |
| 49 | `feature: HTTP/2 and HTTP/3 header inspection` | needs a keylog for h3; h2 is feasible now |
| 50 | `feature: pcapng multi-interface correlation` | one capture, several interfaces, interface id in the flow key |
| 51 | `feature: baseline and diff mode` | `pf analyze --baseline last.json` to show only new findings |
| 52 | `feature: SARIF output` | for code-scanning ingestion in CI |
| 53 | `research: certificate pinning violations` | JA3/JA4 against an allowlist |
| 54 | `research: better server/client orientation` | replace the port heuristic with SDP/JA3S/kex evidence |

## Standing tasks (no issue needed)

* Re-run the corpus and read the reports whenever `tshark` is upgraded.
* Keep `docs/tshark-fields.md` current: a field that moves is a silent-omission bug.
* Re-check the cipher registry when tshark's value table changes (`--refresh`).
