# SMB1_IN_USE

## What it means
The capture contains SMBv1 traffic (an SMB1 header or a negotiate offering SMB1 dialects).

## Why it matters
SMBv1 is deprecated and unsigned by default; it is the protocol targeted by EternalBlue/WannaCry-class exploits, and its use usually marks an unpatched or legacy host.

## How to fix
- Disable SMBv1 on clients and servers.
- Upgrade legacy devices that only speak SMB1, or isolate them.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SMB1_IN_USE must no longer be reported.
