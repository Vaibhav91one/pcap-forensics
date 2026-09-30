# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-09-30

**pcap-forensics is now pcap-doctor**: one command gives a health score, findings grouped by category,
explanations, a CI gate on new findings, and a handoff to AI coding agents. `pf` stays as an alias.
`report.json` keeps `schema_version` `1.4.0`: everything new is computed around the report.

### Added — pcap-doctor

- Distribution and command `pcap-doctor`, `--version`; `npx pcap-doctor` launcher (runs the same
  version through `uvx` or `pipx`); PyPI and npm releases by trusted publishing,
  with no stored token (#46, #50, #51, #93).
- The CLI is a package of self-registering command modules (#45).
- A rule catalog with eight categories, `rules list` / `rules explain`, and a doc per finding code
  (#47, #49, #61).
- A local 0-100 health score and a summary grouped by category; `--score`, `--verbose` (#48, #53).
- `--category`, strict option validation (unknown values exit 2 before tshark runs) (#52).
- `--json` / `--json-out` envelope, `--sarif` (SARIF 2.1.0), `--baseline` to show and gate only new
  findings (#54, #55, #56).
- `pcap-doctor.toml` / `[tool.pcap-doctor]`: `disable`, `[severity]`, `[[allow]]` with a reason,
  `categories`, `fail_on`, and the `ota` profile (`--config`, `--profile`); every suppression is
  noted in the report (#57, #58).
- `why <frame|id>` with `--prompt`; an AI handoff menu after interactive scans (Claude Code, Codex,
  Cursor; `--safe`, `--no-handoff`), agent guidance inside agent shells, and a fenced
  untrusted-data prompt builder (#49, #59, #60).
- `install` writes agent guides (Claude Code skill, Cursor rule, AGENTS.md block) (#62).
- `ci install` and a composite GitHub Action that compares each capture with its base-branch copy,
  comments once on the PR and uploads SARIF (#63).
- `watch -i IFACE`: ring-buffer live capture that prints each finding the first time it appears (#64).
- `HTTP_CLEARTEXT`: plain HTTP is reported per flow, high when a request path looks like a firmware or
  package download (so `--profile ota` fails it) and medium otherwise; query strings are never written
  to a report (#91). A new fixture, `http_cleartext.pcap`, covers it.

### Changed — pcap-doctor

- The npm launcher is published with npm trusted publishing (OIDC) instead of an `NPM_TOKEN` secret;
  the release job skips with a notice when the package is not on npm yet (its first publish is
  manual) or the version is already published (#93).

### Fixed — pcap-doctor

- RFC citations in TLS version and cipher-policy text (#72).
- The tool version in reports now comes from the installed package instead of a hard-coded string (#65).

**MVP hardening since 0.1.0 (issues #1–#44):**

`report.json` `schema_version` is `1.4.0` (additive: `Flow.first_frame`, `Flow` burst statistics,
`RtpStream.first_frame`, `SshSession.offered_in`, `TelnetLogin`).

### Added

- Telnet logins: passwords typed after a `Password:` prompt are reported as `CLEARTEXT_CREDENTIAL`
  (length and frame only, never the text); Telnet sessions now raise `CLEARTEXT_SERVICE` (#37).
- `SSH_TERRAPIN_EXPOSED`: chacha20-poly1305, or an EtM MAC with a CBC cipher, offered without strict
  key exchange on both sides (#24).
- FTP `PASS` arguments and LDAP simple-bind passwords are reported as `CLEARTEXT_CREDENTIAL` (#14).

### Fixed — secrets

- SNMP community strings and MySQL queries are redacted where the index builds service details (#1).
- A scheme-less `Authorization` value (bare token) no longer appears in a finding title or evidence (#15).

### Fixed — evidence and correctness

- Every finding cites a real frame: RTP, SYN scan, odd-port, beaconing and DNS resolver evidence no
  longer cite frame 0 or a stream index (#4, #6); SSH evidence cites the KEXINIT, not the banner (#25).
- The server's SSH KEXINIT no longer overwrites the client's offer (#25).
- `BEACONING_SHAPE` measures regularity of gaps between bursts; the old check could never fail (#10).
- `SERVICE_ON_ODD_PORT` no longer reports a client's ephemeral port (#16).
- `DNS_EXTERNAL_RESOLVER` finds the resolver by port and covers IPv6 and all private ranges (#6);
  `DNS_TUNNEL_SHAPE` names the querying host and no longer counts responses as queries (#18).
- `chacha20-poly1305@openssh.com` is no longer listed as a weak SSH cipher (#2).
- Invalid or wrong finding references replaced (e.g. `CWE- exfil`, RFC 8999 on TLS findings) (#3).
- The service field list is shared with the tshark pass; four names that are not tshark fields were removed (#14).
- `WELL_KNOWN_PORTS`: 506/522/1194 mapped to the wrong service (#23).

### Changed — docs

- README redesigned CLI-first: light/dark logo, badges, a numbered get-started path including a CI
  gate, a table of contents, exit codes, and a privacy/telemetry section; the documented default
  output folder is corrected to `<capture>.pf-report/` (#41).
- CONTRIBUTING gains how-to-start, pull-request and other-ways-to-help sections; a pull request
  template follows the AGENTS.md contract (#41).

### Fixed — project

- Mermaid: `04-diagrams.md` emitted an invalid RTP gantt for captures without RTP (28 of 179 generated
  diagrams failed to render), and the README's sequence diagram broke on a `;` (#43).
- CI could never pass (non-existent tshark preference, fixture drift check on randomly captured TLS
  fixtures); it now runs the full suite (#12).

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
