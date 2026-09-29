# SSH_WEAK_KEX

## What it means
The SSH key-exchange algorithm list offered by either peer includes SHA-1 based exchanges or 1024-bit groups: diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha1, diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha256, rsa1024-sha1, or rsa2048-sha256.

## Why it matters
SHA-1 based exchanges and 1024-bit groups are below current guidance; group exchange can negotiate small groups; the RSA key-exchange methods are not recommended.

## How to fix
- Restrict `KexAlgorithms` in `sshd_config` and client config to modern groups such as curve25519-sha256 or diffie-hellman-group16-sha512.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SSH_WEAK_KEX must not be reported.
