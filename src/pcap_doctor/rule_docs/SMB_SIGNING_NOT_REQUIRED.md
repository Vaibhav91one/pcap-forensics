# SMB_SIGNING_NOT_REQUIRED

## What it means
The server's SMB2/3 NEGOTIATE response does not require message signing.

## Why it matters
Without mandatory signing an on-path attacker can relay NTLM authentication to the server or alter SMB traffic.

## How to fix
- Require SMB signing on the server (Windows policy "Digitally sign communications (always)", Samba `server signing = mandatory`).

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SMB_SIGNING_NOT_REQUIRED must no longer be reported.
