# TLS_WARNING_ALERT

## What it means
A warning TLS alert (level 1, not fatal) was observed in the session, such as no certificate or a close_notify.

## Why it matters
Warning alerts do not kill the session, so they are not themselves an attack; but persistent warnings indicate a peer that is not closing sessions cleanly or is rejecting optional behaviour, which can mask a degraded service.

## How to fix
- Confirm the alert is expected for the protocol (e.g. close_notify on clean shutdown); otherwise fix the peer that emits the warning.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_WARNING_ALERT must not be reported.
