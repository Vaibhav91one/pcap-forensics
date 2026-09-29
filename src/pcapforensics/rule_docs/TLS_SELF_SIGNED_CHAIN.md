# TLS_SELF_SIGNED_CHAIN

## What it means
The leaf certificate's subject equals its issuer, so no certificate authority vouches for it.

## Why it matters
Clients either reject the certificate out of hand or are configured to skip verification; with verification disabled, an on-path attacker can present their own certificate and go unnoticed.

## How to fix
- Issue the leaf from a real certificate authority, or pin the self-signed certificate deliberately and document that decision.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_SELF_SIGNED_CHAIN must not be reported.
