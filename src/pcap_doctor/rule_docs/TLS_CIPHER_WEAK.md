# TLS_CIPHER_WEAK

## What it means
The server selected a cipher suite that is either prohibited or deprecated. Prohibited examples include NULL, export-grade, anonymous, RC4, and ciphers using DES or 3DES. Deprecated examples are static RSA or static (EC)DH key exchange suites that provide no forward secrecy.

## Why it matters
Prohibited suites are broken or revoked and allow recovery of plaintext or session keys. Static key exchange lets a later compromise of the server private key decrypt recorded past traffic.

## How to fix
- Remove prohibited suites immediately; rotate to TLS 1.3 or an AEAD ECDHE suite.
- For nginx: `ssl_protocols TLSv1.2 TLSv1.3;` and `ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;` (TLS 1.3 suites are not set via ssl_ciphers).

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CIPHER_WEAK must not be reported.
