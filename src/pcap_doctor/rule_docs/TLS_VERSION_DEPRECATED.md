# TLS_VERSION_DEPRECATED

## What it means
The TLS or DTLS handshake completed at a negotiated version that is SSL 3.0, TLS 1.0, TLS 1.1, or DTLS 1.0.

## Why it matters
These versions use legacy constructions with known attacks: BEAST against TLS 1.0 block ciphers, and POODLE (CVE-2014-3566) against SSL 3.0. PCI DSS 4.0 forbids them.

## How to fix
- Raise the minimum to TLS 1.2 and prefer TLS 1.3; disable SSLv3, TLS 1.0, and TLS 1.1 on every endpoint.
- For nginx: `ssl_protocols TLSv1.2 TLSv1.3;`.
- For Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`.
- For HAProxy: `bind ... no-sslv3 no-tlsv10 no-tlsv11`.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_VERSION_DEPRECATED must not be reported.
