# SIP_CLEARTEXT_SIGNALLING

## What it means
SIP messages were observed on a flow that was not transported over TLS or SIPS.

## Why it matters
Cleartext SIP exposes the call metadata, method, and any authentication headers. If authentication headers are present, the challenge or response is replayable by anyone on-path.

## How to fix
- Move SIP to SIP over TLS (port 5061) or require TLS for the signalling leg.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SIP_CLEARTEXT_SIGNALLING must not be reported.
