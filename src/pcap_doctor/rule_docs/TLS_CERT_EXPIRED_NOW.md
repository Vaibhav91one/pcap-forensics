# TLS_CERT_EXPIRED_NOW

## What it means
A certificate was valid during the capture but has expired since the capture, checked against today's date.

## Why it matters
The recorded traffic used a then-valid certificate, so the historical session is not retroactively invalid; however the current deployment is now broken and new connections will fail.

## How to fix
- Renew the certificate and redeploy before it is needed by live clients.

## How to verify
After renewing, capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CERT_EXPIRED_NOW must not be reported.
