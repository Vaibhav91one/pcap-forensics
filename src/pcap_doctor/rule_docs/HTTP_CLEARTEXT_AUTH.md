# HTTP_CLEARTEXT_AUTH

## What it means
An HTTP exchange sent an Authorization header (Basic, Digest, Bearer, or any other scheme) over a cleartext HTTP flow without TLS.

## Why it matters
Anyone on-path can read and replay the credential, including Basic base64 tokens, Digest responses, and bearer tokens sent without TLS.

## How to fix
- Terminate TLS on the service and redirect HTTP to HTTPS.
- Move to a token scheme with short expiry; never send Basic over cleartext.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; HTTP_CLEARTEXT_AUTH must not be reported.
