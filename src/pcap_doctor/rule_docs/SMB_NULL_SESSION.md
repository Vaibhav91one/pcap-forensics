# SMB_NULL_SESSION

## What it means
An SMB session was authenticated with an empty NTLM identity (a null session).

## Why it matters
Null sessions let anyone enumerate users, shares and policies, a common first step before password guessing.

## How to fix
- Set RestrictAnonymous and disable anonymous SID/name translation.
- Disable guest access to shares.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SMB_NULL_SESSION must no longer be reported.
