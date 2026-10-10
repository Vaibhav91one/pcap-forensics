# SMB_ADMIN_SHARE_ACCESS

## What it means
A client connected to an administrative share (ADMIN$ or a drive share such as C$).

## Why it matters
Administrative shares give file-system level access and are used by remote administration and by lateral-movement tools.

## How to fix
- Confirm the access is expected administration.
- Restrict admin shares to jump hosts; disable them where unneeded.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SMB_ADMIN_SHARE_ACCESS must no longer be reported.
