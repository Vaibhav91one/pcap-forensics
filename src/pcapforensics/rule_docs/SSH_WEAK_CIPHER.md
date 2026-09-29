# SSH_WEAK_CIPHER

## What it means
The SSH cipher list offered by either peer includes any of the CBC or RC4/3DES/Blowfish/CAST128 variants: aes128-cbc, aes192-cbc, aes256-cbc, 3des-cbc, arcfour, arcfour256, arcfour128, blowfish-cbc, or cast128-cbc.

## Why it matters
CBC modes allow plaintext-recovery attacks, RC4 (arcfour) is broken, and 3DES, Blowfish, and CAST128 use 64-bit blocks that are within practical collision range.

## How to fix
- Remove the weak ciphers from `Ciphers` in `sshd_config` and client config; require AES-GCM or chacha20-poly1305.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SSH_WEAK_CIPHER must not be reported.
