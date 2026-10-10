# TLS_OFFERS_WEAK_CIPHERS

## What it means
The client offered one or more prohibited or deprecated cipher suites in its ClientHello that the server did not select.

## Why it matters
These suites are downgrade surface: a future negotiation or an active attacker steering cipher selection could force a weak suite. Offering them also signals an outdated or misconfigured client.

## How to fix
- Restrict the client cipher list to AEAD suites with ephemeral key exchange (TLS 1.3 recommended).
- Remove legacy cipher strings from client TLS configuration.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_OFFERS_WEAK_CIPHERS must not be reported.
