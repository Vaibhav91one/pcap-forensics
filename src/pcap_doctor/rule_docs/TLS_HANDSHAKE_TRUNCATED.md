# TLS_HANDSHAKE_TRUNCATED

## What it means
A TLS or DTLS ClientHello was seen in a flow but no ServerHello ever arrived within the capture window, so the handshake never completed.

## Why it matters
A handshake that starts but never completes is typical of a port scan, a firewall probe, or a capture that begins mid-handshake. It indicates the service's liveness and encryption posture could not be confirmed for that conversation.

## How to fix
- Confirm whether the host is actually a TLS or DTLS service; if it is not, close the port or stop the probe.
- If the capture is mid-stream, re-capture from the start of the conversation.

## How to verify
Capture the full conversation again and run `pcap-doctor analyze <capture>`; TLS_HANDSHAKE_TRUNCATED must not be reported.
