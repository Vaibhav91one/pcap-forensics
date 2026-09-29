# TLS_CERT_WEAK_KEY

## What it means
The certificate key is below current guidance: RSA below 2048 bits (below 1024 is worse) or an elliptic-curve key below 256 bits (below 224 is worse).

## Why it matters
Keys below guidance are within range of feasible computation or factoring, letting an attacker recover the private key and impersonate the service or decrypt recorded traffic.

## How to fix
- Reissue with at least a 2048-bit RSA key or a P-256 (or stronger) EC key.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CERT_WEAK_KEY must not be reported.
