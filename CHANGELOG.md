# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-29

First working release. `report.json` `schema_version` is `1.0.0`.

### Added — parsing

- `TsharkRunner`: 10 pinned tshark passes, `-T fields` with a documented
  separator/aggregator, content-addressed disk cache keyed by capture SHA-256,
  tshark version and pass arguments.
- Field and display-filter drift handling: fields validated against
  `tshark -G fields`, protocol tokens against `tshark -G protocols`, preferences
  against `tshark -G defaultprefs`; every drop recorded as a report note.
- `CaptureIndex`: flows, hosts, TLS/DTLS sessions, HTTP exchanges, DNS queries,
  SIP messages with SDP, RTP streams, SSH sessions, QUIC sessions, and other
  recognised services.
- SDP-driven RTP decode-as, so media on dynamic ports is dissected at all.
- Certificate enrichment through `openssl x509`, with an explicit
  `name_source` field and a tshark-flattened fallback.
- Cipher registry of 424 suites derived from tshark's own value table, with
  weakness tags and forward-secrecy reasoning derived from the IANA name.

### Added — detectors

- `d1.tls_cipher`: deprecated versions, weak/prohibited suites, offered-but-unused
  weak suites, missing forward secrecy, certificate expiry/key size/signature,
  self-signed leaf, alerts, truncated handshakes, JA3 fleet clustering.
- `d2.transport_exposure`: cleartext HTTP auth, Basic auth inside TLS, cookies
  without `Secure`, cleartext services, leaked credentials, services on odd
  ports, unanswered-SYN scan shape, beaconing shape.
- `d3.sip_rtp`: SIP call graph, cleartext signalling with auth headers, SDP
  without `a=crypto`, unprotected RTP, media volume anomalies.
- `d4.dns_quic_ssh`: plaintext DNS leakage, DNS tunnelling heuristics, external
  resolvers, QUIC version inventory and payload opacity, weak SSH negotiation.

### Added — output

- Six artifacts per run: `index.md`, `01-flows.md`, `02-ciphers.md`,
  `03-findings.md`, `04-diagrams.md`, `report.json`.
- Mermaid topology, crypto matrix, severity pie, per-detector bar chart, RTP
  timeline and SIP sequence diagrams, all total functions.
- Stable finding ids (`detector.code.sha256(scope)[:16]`) so reports diff.
- `pf` CLI: `analyze`, `flows`, `ciphers`, `detectors`, `suites`, `doctor`,
  `schema`, with `--fail-on` for CI gates.

### Added — safety

- Credential redaction at the model boundary, with tests that grep the artifacts
  for the original material.
- One detector raising an exception cannot sink a run; it is reported as a note.
- Unknown cipher ids, unparseable certificates and missing tshark fields all
  produce findings or notes, never silent passes.

### Added — engineering

- 85 tests across four layers: registry, tshark boundary, detectors with
  synthetic fixtures, and regression assertions over the Wireshark sample
  corpus checked by hand against `tshark -V`.
- Fixtures generated deterministically; TLS fixtures captured from genuine
  OpenSSL handshakes through a logging proxy.
- `ruff`, `mypy --strict` and `pytest` are the CI gate (`make verify`).
- `AGENTS.md` and `docs/subagent-playbook.md`: the subagent isolation contract
  and a 54-item seed issue board (`docs/issue-board.md`).

### Known limits

- Encrypted payloads (QUIC, TLS 1.3 application data) are opaque without a keylog.
- Certificate subject/issuer require openssl; without it the report says so.
- DNS tunnelling and beaconing are heuristics, reported at low confidence.
- Server/client orientation uses port heuristics; odd ports are flagged instead
  of trusted.
