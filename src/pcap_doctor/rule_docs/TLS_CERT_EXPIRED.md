# TLS_CERT_EXPIRED

## What it means
A certificate in the TLS chain had already expired before the capture ended, so it was invalid when the handshake was served.

## Why it matters
An expired certificate means the TLS identity was not trustworthy for the recorded traffic and a validating client should have rejected the connection.

## How to fix
- Renew and deploy the certificate immediately.
- Automate renewal and alerting on expiry (e.g. certbot, acme.sh, or a PKI issuer).

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CERT_EXPIRED must not be reported.
