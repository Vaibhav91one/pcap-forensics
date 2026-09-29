# TLS_LEGACY_RECORD_VERSION

## What it means
A TLS or DTLS record carries an older version (SSL 3.0, TLS 1.0, TLS 1.1, or DTLS 1.0) in its record-layer version field than the version the session negotiated.

## Why it matters
On a ClientHello this field reading TLS 1.0 is normal, because that is the sentinel the client sends before version negotiation. It only matters on post-handshake records, which some older peers downgrade to, weakening the record layer.

## How to fix
- No action is required unless the legacy version appears on post-handshake application records.
- If it does, upgrade the peer stack so it only emits the negotiated version on data records.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; the legacy record version must not appear on post-handshake records.
