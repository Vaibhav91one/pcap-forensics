# BEACONING_SHAPE

## What it means
A flow carried at least 6 bursts of traffic (5 or more gaps between them) and the gaps were very regular: their coefficient of variation was 0.1 or below.

## Why it matters
Near-constant inter-burst gaps match implant-style periodic check-in behaviour, but the same pattern also arises from scheduled jobs; timing alone cannot confirm a beacon.

## How to fix
- Correlate the callback interval with known job schedules for the endpoints.
- If unexplained, isolate the host and inspect the flow subjects.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; BEACONING_SHAPE must not be reported if the periodicity is explained or removed.
