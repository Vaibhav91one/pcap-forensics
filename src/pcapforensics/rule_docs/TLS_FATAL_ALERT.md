# TLS_FATAL_ALERT

## What it means
A fatal TLS alert (level 2) was observed in the session, such as a handshake failure or a rejected certificate.

## Why it matters
A fatal alert tears the session down and signals a failed negotiation or a rejected client, which can indicate a misconfigured service or an active probing/scanning campaign.

## How to fix
- Correlate the alert description with server logs; bad certificate or certificate required point at a missing or mismatched certificate.
- If the alert is from a scanner, allowlist its behaviour or rate-limit it.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_FATAL_ALERT must not be reported.
