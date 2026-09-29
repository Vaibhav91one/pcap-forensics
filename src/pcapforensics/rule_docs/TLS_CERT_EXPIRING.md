# TLS_CERT_EXPIRING

## What it means
A certificate is still valid at the capture end time but expires within 30 days of the capture.

## Why it matters
The certificate will expire soon after capture, so the same service will begin failing unless renewed. Short-lived certificates make this a near-term operational risk.

## How to fix
- Renew the certificate now and confirm automated renewal and expiry alerting are in place.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_CERT_EXPIRING must not be reported.
