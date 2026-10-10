# TLS_CIPHER_UNKNOWN

## What it means
The server chose a cipher suite id that is not in pcap-doctor's cipher registry, so its security properties cannot be judged automatically.

## Why it matters
An unrecognised suite cannot be checked against policy, so the connection's cryptographic strength is unknown. GREASE values are expected; private values require manual review.

## How to fix
- Identify the suite value (reported as `0x<hex>`) against the IANA TLS Cipher Suite Registry.
- If it is GREASE, confirm the peer filters those values on the receiving side.
- If it is a private suite, document its security properties or disable it.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CIPHER_UNKNOWN must not be reported.
