# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Rename finished.** The internal import package is now `pcap_doctor` (was `pcapforensics`): `python -m pcap_doctor.cli`,
  `from pcap_doctor import ...`. The pip distribution, the `pcap-doctor` command, the `pf` alias and the doctor/1 tool id are
  unchanged. All GitHub URLs, badges and the Action reference now point to `doctor-labs/pcap-doctor`
  (`uses: doctor-labs/pcap-doctor@v...`). `PCAP_FORENSICS_CACHE` is still honoured.

### Added

- `pcap-doctor packets` and `pcap-doctor packet`: a per-packet explorer over the capture. `packets` lists frames (number, time, source, destination, protocol, length, info) and takes a Wireshark display filter with `-Y`; `packet CAPTURE FRAME` prints the full dissection tree and the hex view of one frame (`--json` for the nested tree, `--no-hex` to drop the dump). Read-only: tshark is asked for exactly what was requested.

## [0.8.0] — 2026-10-09

Machine output now follows the shared **doctor/1** contract (`docs/doctor-contract.md`). This is a
breaking change to `--json`, `--json-out`, `--sarif`, `--baseline` and the exit codes; there is no
legacy flag. `report.json` on disk and its `schema_version` (1.6.0) are unchanged.

### Changed (breaking)

- **`--json` / `--json-out`** print `{schema: "doctor/1", tool, version, exit_code, score: {value, label,
  model, coverage_gaps}, findings, data}`. The old `{tool, version, score, label, categories, report}` is gone:
  the old `report` (without its findings) and `categories` are under `data`, and `new_findings` became
  `baseline_state` on each finding plus a top-level `baseline: {new, unchanged, fixed}`.
- **Findings** in the envelope use the contract keys: `id` is the rule code, `fingerprint` a 16-hex
  identity (client ephemeral port masked), `message` the title, `remedy` the remediation, `location`
  `{kind, ref}`, `evidence` `[{ref, value}]`. The old per-run id is kept as `finding_id`.
- **Exit codes:** with `--baseline`, a new finding at or above `--fail-on` exits **3** (was 1);
  `analyze` exits 130 on SIGINT.
- **Score labels** are `good` (>= 90), `needs work` (>= 60), `critical`; the formula is unchanged and named `pcap/1`.
- **`--baseline`** matches by `fingerprint` only and reads a doctor/1 envelope (a `report.json` still works).
- **SARIF:** the fingerprint key is `doctorFinding/v1` (was `pcapDoctorFindingId/v1`) and runs carry `properties.score`.
- `pcap-doctor schema` reports `doctor/1` next to the report schema version; `pcap-doctor why` also accepts a fingerprint.

### Added

- `pcap-doctor mcp`: an MCP server over stdio (11 tools: analyze, why, rules_list, rules_explain, keys_scan, flows,
  ciphers, detectors, suites, doctor, schema). `analyze` returns the doctor/1 envelope unchanged; `watch`,
  `install` and `ci install` are not exposed (README, "MCP server").
- `docs/doctor-contract.md` and a conformance test (`tests/test_doctor_contract.py`), including an escape-sequence
  test through the human renderers.

## [0.7.0] — 2026-10-05

Every change in this release was found by stress-testing the tool against real firmware images and
real captures rather than against its own fixtures. Two rounds of that work turned up defects in
`keys scan` and in the TLS certificate path; a third found a way for attacker-chosen capture text to
reach a report with raw terminal escapes still in it.

Report schema **1.5.0 → 1.6.0**.

### Fixed

- **A DSA key was judged by the RSA threshold and described as RSA.** `weak_key_verdict` had an
  elliptic-curve branch and then an RSA rule that everything else fell into, so a 1024-bit DSA key was
  reported as `"RSA keys below 2048 bits are outside current guidance"`. A DSA prime size is not
  comparable with an RSA modulus, so it is now reported as undecided with a reason rather than
  borrowed (#155, #152).
- **Elliptic-curve keys were flagged `weak-key-256bit`.** The `bits` field holds a modulus size for
  RSA and a curve size for EC, and one threshold was applied to both -- so a NIST-recommended P-256 key
  read as breakable. Strength is now decided per algorithm (#144, #153).
- **A certificate's key size was never read,** so a shipped 768-bit RSA certificate produced no
  weakness flag at all. Certificates now report their algorithm and their RSA modulus size (#143, #146,
  #149, #159).
- **`TLS_LEGACY_RECORD_VERSION` fired 26 times across the corpus and every one was the ClientHello
  sentinel** that RFC 8446 and RFC 5246 require and tell readers to ignore. The record layer now
  keeps a frame and a content type per record, so the post-handshake case -- a peer that really would
  downgrade -- is distinguished from the sentinel instead of being reported as inventory (#157, #164,
  #150, #158).
- **An attacker-chosen HTTP `Host` header reached `03-findings.md` with raw ANSI escapes intact,**
  including a screen clear followed by red text reading "no findings" -- in the file the README tells
  people to paste into a ticket. `keys scan`'s table had the same problem with a firmware file name,
  which rich would additionally have displayed as a path the analyst does not have (#167, #170, #172,
  #169, #173, #174, #176).
- **`keys scan --json` returned the raw escape,** because `json.dumps` encodes it as a six-character
  sequence. It is a machine surface, so the value is now filtered at the envelope (#175, #177).
- **The `watch` signal test raced the process reaper,** failing intermittently under load (#179).
- `keys scan` applies the published curve policy (#162, #165), and an unreadable certificate is now a
  row that says why instead of vanishing (#163).

### Changed

- Capture-chosen text is filtered once, where a finding is built, and again only where a surface
  needs something different: a terminal additionally escapes markup, a JSON surface deliberately does
  not. The rule is written down in AGENTS.md so the asymmetry is not "harmonised" into a bug (#171,
  #172).

### Added

- A real-world stress corpus: 141 OpenWrt firmware images across seven releases, 219 captures from the
  wireshark test suite, and 49 key-material vectors, each with the properties it must be expected to
  report (#141, #142, #145, #147).
- Harnesses that cross-check the tool against tshark, check its report contract, plant adversarial
  capture text, and **prove they would still notice if the tool regressed** (#154, #160, #168, #178,
  #180, #181, #182, #183, #184).

### Known limits, unchanged

- No fixture covers a genuine downgraded TLS application record; the positive path is covered by unit
  tests over a constructed session (#166).
- There is deliberately no DSA threshold (#155) and no minimum-curve policy in `keys scan` beyond the
  published floor (#151).


## [0.6.0] — 2026-10-03

Closes the caveats left after 0.5.0: re-captures match their baseline, live `watch` is proven and stops
cleanly, firmware downloads are recognised from the response headers, and indexing is about twice as fast.

### Fixed

- `watch` prints a finding once, not again for every new client connection to the same service: it dedupes
  on the same port-insensitive match as `--baseline` (#136).
- `--baseline` no longer reports every finding as new when the same device is captured again: a finding is
  known when only its client's ephemeral port changed (detector, code, title and flow key are compared with
  the higher port of each flow masked). Finding ids are unchanged (#126).

### Changed

- CI copies through `wl-copy` under a real headless Wayland compositor (sway) and reads it back with
  `wl-paste`, so the Wayland clipboard path is proven like X11, macOS and Windows already were (#129).
- A plain-HTTP firmware download is also recognised from the response: a `Content-Disposition` file name with a
  firmware extension, or a firmware-only content type (`application/x-firmware`,
  `application/vnd.android.ota-package`, `application/x-ota-package`); the evidence names the header that fired.
  `application/octet-stream` alone is not a signal. Existing findings are unchanged (#130).
- `watch` prints the exact command that grants live-capture rights on this OS (macOS ChmodBPF / `access_bpf`,
  Linux `wireshark` group or `setcap` on dumpcap, Windows Npcap) when capturing fails. CI now runs a real
  `watch -i lo` capture on Linux and checks a finding comes out and no capture process is left. `watch` now
  also stops cleanly on SIGTERM and when started in the background (`watch &` ignores Ctrl-C's SIGINT);
  before, both left dumpcap running (#128).
- Indexing runs the independent tshark passes concurrently (RTP still waits for SIP). Reports are identical;
  on a 120 MB / 509k-packet capture `analyze` took 41 s instead of 91 s, at about +0.8 GB peak memory (#127).

## [0.5.0] — 2026-09-30

White-box firmware testing: decrypt a capture with key material you supply, inventory the keys an
image ships, and flag a server key that ships in the firmware. Plus cross-platform CI.

### Added

- **Decrypt your own capture with key material you supply** (authorized white-box testing). `analyze` gains
  `--tls-key FILE` (repeatable), `--tls-key-password`, `--keys-from DIR` (every PEM private key under an
  extracted-firmware tree), `--keylog FILE` and `--psk HEX`. An RSA private key decrypts RSA-key-exchange
  sessions (no forward secrecy) that match the server certificate; decrypted inner HTTP then flows through the
  existing detectors, and a `[decrypt] read inner traffic from N of M TLS session(s)` note is added. Key
  material is passed straight to tshark and never written to any artifact (#115).
- `pcap-doctor keys scan DIR` inventories the key material in an already-extracted firmware tree: every PEM
  private key and certificate, flagged for weak keys (<=1024-bit RSA), self-signed, expired, and — the
  dangerous one — a private key whose public half matches a shipped certificate (you hold the key for that
  cert). `--json` for the machine form; `--out KEYS_DIR` normalises the private keys for
  `analyze --keys-from`. Private-key bytes are never printed (#117).
- Each certificate now carries a public-key fingerprint `spki_sha256` (the non-secret
  `sha256(DER public key)[:16]`), so a key seen on the wire can be matched against a private
  key found in firmware. Report schema bumped to **1.5.0** (#119).
- `analyze --firmware DIR` (repeatable) correlates the capture against an extracted-firmware tree:
  when a session's server certificate has the same public key as a private key in the image,
  pcap-doctor reports **`TLS_KEY_IN_FIRMWARE`** (critical) — the key that protects this channel
  ships in every device, so anyone with the image can passively decrypt and tamper with it. Keys
  supplied via `--tls-key`/`--keys-from` are correlated too. Only the non-secret SPKI fingerprint
  and the firmware path appear in the report (#121).

- CI proves pcap-doctor on **Linux, macOS and Windows**:
  - tshark from each OS's package manager;
  - the same finding codes on every fixture (`tests/fixtures/expected_codes.json`);
  - every command run with piped output;
  - a real clipboard round trip;
  - the full test suite on macOS (#108).
- The npm package has a README, and the PyPI page links the repository, issues and changelog. README
  images and links are absolute, so they work on PyPI and npm (#105).

### Changed

- The tshark cache is set with `PCAP_DOCTOR_CACHE` and defaults to `~/.cache/pcap-doctor`; the older
  `PCAP_FORENSICS_CACHE` is still honoured (#112).

### Fixed

- Copy on Windows goes through PowerShell's `Set-Clipboard`. `clip.exe` put an invisible byte-order
  mark (U+FEFF) at the start of the copied text; a real Windows runner caught it (#108).
- `pcap-doctor.toml` or `[tool.pcap-doctor]` is found from subfolders, up to the repository root. Before,
  a run from `captures/` silently ignored the repository's config (#106).

- The interactive text screens scroll. Show findings report, Show fix prompt, the workflow and the
  launch preview used to show only their first lines and looked stuck. Keys: ↑/↓, PgUp/PgDn, Space,
  g/Home and G/End. Lines wrap to the terminal, so the key footer always stays visible (#104).

## [0.4.0] — 2026-09-30

Findings reports for security testers, and copying that works on every machine.

### Added

- *Choose how to continue* copies or shows a **findings report**: a security-weakness report in
  Markdown for one finding or all of them. Review's enter copies it for the selected finding, and
  **s** saves it (#101).

### Fixed

- Copy works everywhere. It picks the clipboard tool that fits the session (`pbcopy`, `wl-copy`,
  `xclip`, `xsel`, `clip.exe`, `termux-clipboard-set`) and says "copied" only on success. Otherwise it
  uses OSC 52 and also saves the text next to the report. A stock Ubuntu, with no clipboard tool,
  previously just failed (#101).

## [0.3.0] — 2026-09-30

Interactive results in the terminal, for security testers and developers.

### Added

- Interactive results after a scan in a terminal, modelled on React Doctor. A spinner shows each stage,
  then the score header with the potential score after priority fixes, then an arrow-key menu:
  - **Review**: findings grouped by category, with impact, evidence, fix and rule guide; enter copies
    ticket-ready text.
  - **Add to GitHub Actions**.
  - **Hand off to an agent**, with the prompt always previewed.

  Piped output, files, CI, `--json`, `-q` and `--score` are unchanged (#98).

### Fixed

- The npm launcher's tests run on Node 20 and 22; `node --test test/` failed on Node 22, which the
  release job uses (#96).

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
