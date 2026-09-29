# DNS_EXTERNAL_RESOLVER

## What it means
A public IP address answered DNS queries in this capture instead of an internal resolver.

## Why it matters
Routing internal names through an external resolver bypasses internal DNS filtering and logging and can leak internal names to a third party.

## How to fix
- Force DNS through the internal resolver and block outbound port 53 and 853 at the perimeter.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; DNS_EXTERNAL_RESOLVER must not be reported.
