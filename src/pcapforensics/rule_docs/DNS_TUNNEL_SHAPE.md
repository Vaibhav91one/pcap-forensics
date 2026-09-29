# DNS_TUNNEL_SHAPE

## What it means
One querier sent at least 12 DNS queries, and at least 12 of them were long names (5 or more labels) or TXT/NULL queries. Severity rises from medium to high when 8 or more of the long names have high character entropy (above 3.5 bits per character).

## Why it matters
That query volume, label depth, and entropy profile is the shape of DNS tunnelling (iodine, dnscat), though it also matches aggressive CDN, RPKI, or service-discovery traffic; it is a heuristic.

## How to fix
- Inspect the queried names against an allowlist and block direct outbound DNS.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; DNS_TUNNEL_SHAPE must not be reported if the queries are legitimate.
