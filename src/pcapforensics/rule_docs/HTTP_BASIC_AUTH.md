# HTTP_BASIC_AUTH

## What it means
An HTTP exchange used HTTP Basic authentication over TLS.

## Why it matters
Basic sends the reusable password with every request, so anything that sees the decrypted traffic (a TLS-terminating proxy, request logs) obtains the password itself rather than a short-lived token.

## How to fix
- Prefer token or OAuth bearer authentication with short expiry over Basic.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; HTTP_BASIC_AUTH must not be reported.
