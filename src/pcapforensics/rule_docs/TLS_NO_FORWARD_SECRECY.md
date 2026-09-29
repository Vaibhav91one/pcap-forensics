# TLS_NO_FORWARD_SECRECY

## What it means
The negotiated cipher suite used static (non-ephemeral) key exchange, so the session has no forward secrecy.

## Why it matters
With static key exchange, a later compromise of the server private key lets an observer decrypt all recorded past traffic on this session.

## How to fix
- Prefer ECDHE or DHE suites or TLS 1.3, which provides forward secrecy by construction.
- Disable static-RSA key-transport ciphersuites.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_NO_FORWARD_SECRECY must not be reported.
