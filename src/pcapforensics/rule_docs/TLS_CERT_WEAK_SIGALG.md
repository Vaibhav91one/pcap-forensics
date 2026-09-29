# TLS_CERT_WEAK_SIGALG

## What it means
The certificate is signed with a signature algorithm of MD2, MD4, MD5, or SHA-1.

## Why it matters
These hash functions are collision-broken or withdrawn: an attacker who gets one certificate signed can craft a different certificate that carries the same valid signature.

## How to fix
- Reissue with a SHA-256 or stronger signature (sha256WithRSAEncryption or ecdsa-with-SHA256).
- Remove SHA-1 from the issuing CA's signature-algorithm list.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CERT_WEAK_SIGALG must not be reported.
