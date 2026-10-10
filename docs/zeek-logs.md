# Zeek-style logs

`pcap-doctor logs CAPTURE [-o DIR] [--format tsv|json|both] [--only conn,dns,...]` writes per-protocol logs with
Zeek's column names and types, so `zeek-cut`, Brim and SIEM parsers read them. `--format tsv` is Zeek's own file
(`#separator`, `#fields`, `#types`, `-` for unset, `(empty)`, `,` inside sets and vectors); `json` is one object
per line with unset fields left out. Every table is also a query source: `pcap-doctor query CAPTURE EXPR -s log:conn`.

| Log | One row per | Built from |
|---|---|---|
| `conn` | TCP/UDP connection, originator = first sender | `conn` pass (flags, lengths) |
| `dns` | query, with its answers and rcode | `dns` pass |
| `http` | request/response exchange | `http` pass |
| `ssl` | TLS/DTLS session: version, cipher name, SNI, ALPN, JA3/JA3S, certificate ids | `tls` pass |
| `x509` | certificate in a handshake | `tls` pass |
| `files` | HTTP body that names a type or a file | `http` pass |
| `notice` | pcap-doctor finding (`note` = finding code) | the detectors |
| `weird` | tshark expert warning or error (malformed packet, bad length...) | `weird` pass |
| `dhcp` | DHCP transaction (xid) | `dhcp` pass |
| `ftp` | FTP command and its reply | `ftp` pass |
| `smtp` | mail transaction (`MAIL FROM` ... `QUIT`) | `smtp` pass |
| `ssh` | SSH session: banners and the first-offered algorithms | `ssh` pass |
| `smb` | SMB/SMB2 command or response, tree, file name, NTLM user | `smb` pass |

## Where the logs differ from Zeek

- `conn.orig_bytes` / `resp_bytes` are TCP/UDP payload bytes seen in the capture (no sequence-number accounting, so a
  retransmission counts twice); `*_ip_bytes` are IP total lengths; `missed_bytes` is always 0.
- `history` is approximated from the SYN/ACK/data/FIN/RST flags (upper case originator, lower case responder; runs of
  the same letter collapse). `conn_state` follows Zeek's definitions (`S0`, `S1`, `SF`, `REJ`, `RSTO`, `RSTR`, `S2`,
  `S3`, `RSTOS0`, `OTH`) from the same counts.
- `uid` is `C` plus 16 hex characters derived from the flow key, stable across runs, not Zeek's random id.
- Secrets are never written: FTP `PASS` is `<hidden>`, no HTTP Authorization or cookie values, no SMTP AUTH data.
- `weird` names are slugs of tshark's own expert messages, not Zeek's weird names (a catalog is tracked in #210).
- The pcap-doctor `ssl` log has no `validation_status` yet (#260). `files` lists the files `extract` recovers, with `seen_bytes`, `md5`, `sha1`, `sha256` and a magic-byte `mime_type`; only HTTP files carry hosts and a connection uid.
- `#open` / `#close` carry the capture's first and last packet time, so two runs give identical files.
