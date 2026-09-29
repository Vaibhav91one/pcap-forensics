# SYN_SCAN_SHAPE

## What it means
One IP initiated at least 5 TCP conversations that never completed a three-way handshake.

## Why it matters
A burst of unanswered SYNs is the signature of a port scan or a host whose port range is filtered, indicating reconnaissance or reachability probing.

## How to fix
- Block or rate-limit the source IP at the perimeter.
- If this was authorised testing, record the authorised window.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SYN_SCAN_SHAPE must not be reported from that source.
