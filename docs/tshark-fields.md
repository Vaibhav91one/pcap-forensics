# tshark field inventory

The analyzer depends on tshark's field names. This file is the human-readable inventory, and
`tests/test_tshark_layer.py` is the machine-enforced version: it fails CI when a required field
disappears from the build in use.

Last verified against **TShark 4.6.6 (Wireshark 4.6.6)** on macOS.

## Why this file exists

Field names move between releases. `dtls.desegment_dtls_records` does not exist in 4.6.6, and
`tls.handshake.ciphersuites` is a *count* in modern builds, not the list. Both mistakes are silent
unless something checks.

`TsharkRunner` therefore validates every field against `tshark -G fields` and every bare protocol
token against `tshark -G protocols`, drops what a build does not know, and records each drop in
`report.notes`. The notes are part of the report, not debug output.

## Passes

| Pass | Display filter | What it extracts |
|---|---|---|
| `base` | *(none)* | frame number/epoch/length, protocol stack, IPv4+IPv6 addresses, TCP/UDP ports and streams, SYN/FIN/RST flags, ARP, ICMP, `_ws.col.Protocol` |
| `tls` | `tls.handshake \|\| tls.alert_message` | handshake types, legacy version, record versions, cipher suites, SNI, ALPN, supported versions/groups, JA3/JA3S, alerts, full certificate DER, X.509 RDNs/validity/SAN |
| `dtls` | `dtls.handshake \|\| dtls.alert_message` | identical field set, `dtls.` prefix; the index folds the prefix so one parser serves both |
| `http` | `http.request \|\| http.response` | method, host, uri, version, status, user agent, authorization, cookies |
| `dns` | `dns` | query name/type, response flag, rcode, answers, TXT, `dns.id` |
| `sip` | `sip \|\| sdp` | method, status, status line, call id, CSeq, from/to user, user agent, via, auth, SDP media/ports/crypto |
| `rtp` | `rtp` | SSRC, payload type, sequence, timestamp |
| `ssh` | `ssh` | protocol banner, kex, host key, cipher, MAC, compression algorithms |
| `quic` | `quic` | versions, long header type, inner SNI/ciphers/ALPN |
| `services` | `ntp \|\| tftp \|\| ftp \|\| ftp-data \|\| telnet \|\| snmp \|\| ldap \|\| smtp \|\| imap \|\| pop \|\| resp \|\| mysql` | per-protocol detail that can contain credentials |
| `ipv6` | `ipv6` | hop limit, payload length |

## Fields with traps

| Field | Trap |
|---|---|
| `tls.handshake.ciphersuites` | a **count** in current builds. The offered list is the repeated `tls.handshake.ciphersuite`; reading only the first occurrence reported "1 suite offered" for a 27-suite ClientHello. |
| `tls.record.version` on a ClientHello | a legacy field that routinely reads TLS 1.0 even when the session negotiates TLS 1.2/1.3. Never report it as the negotiated version. |
| `x509af.subject` / `x509af.issuer` | RDN **OIDs**, not names. tshark gives no subject/issuer split for field output; use openssl (see `certificates.py`). |
| `x509af.utcTime` | two values per certificate (notBefore, notAfter). Chain length is `len(utcTime) // 2`. |
| `x509ce.modulus` | empty for EC keys, and the RSA modulus is not always exposed as a field. Key size comes from openssl, with the curve OID as a fallback. |
| `tcp.flags.*` | render as `True`/`False` in `-T fields` on some builds and `1`/`0` on others. `to_bool01` accepts both; a build that emitted only `1`/`0` silently produced "0 SYNs" before that was fixed. |
| `rtp.ssrc` | hexadecimal with an `0x` prefix. Decimal parsing turns it into `None`. |
| `dtls.handshake.version` | OpenSSL < 0.9.8f encodes DTLS 1.0 as `0x0100`, not `0xFEFF`. Both map to DTLS 1.0. |
| `_ws.col.*` | not listed by `tshark -G fields` but perfectly valid; never dropped. |
| RTP on dynamic ports | tshark does not dissect RTP on arbitrary ports. The index reads SDP `m=` lines and passes `-d udp.port==<port>,rtp`, which is how media on a dynamic port is judged at all. |

## Certificate facts

tshark's field output flattens X.509 into unordered RDN strings. The authoritative route:

```
tls.handshake.certificate   ->   raw DER, one occurrence per certificate
DER  ->  ssl.DER_cert_to_PEM_cert  ->  openssl x509 -noout -text -nameopt RFC2253
```

which yields exact subject, issuer, validity, public key size, signature algorithm, SANs and
`CA:TRUE/FALSE`. When openssl is unavailable the report keeps the tshark-derived values, sets
`name_source = "tshark-flattened"`, and adds a note.

## Checking your own build

```bash
pcap-doctor doctor                                     # field and preference inventory
tshark -G fields | rg 'tls.handshake.cipher'  # does this build name it the way we expect?
tshark -r capture.pcap -Y 'tls.handshake.type==2' -T fields -e tls.handshake.ciphersuite
make typecheck                                 # nothing here is typed against a generated stub
```
