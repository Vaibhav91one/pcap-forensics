# DNS_CLEARTEXT

## What it means
A DNS query, not sent over DNS-over-TLS or DNS-over-HTTPS, was observed on a flow with no encryption layer. Reverse (`.arpa`) and local-area (`.local`) lookups are not reported.

## Why it matters
Cleartext DNS exposes the queried names and answers to any on-path observer, revealing the hosts and services the client is reaching, and bypasses internal DNS filtering and logging.

## How to fix
- Use DNS-over-TLS (port 853) or DNS-over-HTTPS, and enforce it in the resolver.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; DNS_CLEARTEXT must not be reported.
