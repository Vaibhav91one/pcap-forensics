# RTP_VOLUME_ANOMALY

## What it means
A single RTP stream carried at least 50% of the total observed RTP bytes across the capture, or the capture carried less than 50000 bytes of RTP in total.

## Why it matters
One stream dominating the volume may indicate a long call, a loopback, or duplicated capture interface traffic rather than a defect; it is a flag for a reviewer, not an automatic failure.

## How to fix
- No action is required unless the volume is unexpected; confirm the capture point did not duplicate traffic.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; RTP_VOLUME_ANOMALY must not be reported if the anomaly is removed.
