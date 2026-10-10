# SMB_EXECUTABLE_ON_SHARE

## What it means
An executable or script (exe, dll, bat, ps1...) was opened over SMB.

## Why it matters
Writing a binary to a remote share (especially ADMIN$) is the staging step of remote execution and worm-like spread.

## How to fix
- Verify the file and the account that wrote it.
- Restrict write access to shares; enable application allow-listing.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SMB_EXECUTABLE_ON_SHARE must no longer be reported.
