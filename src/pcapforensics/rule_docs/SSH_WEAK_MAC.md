# SSH_WEAK_MAC

## What it means
The SSH MAC algorithm list offered by either peer includes a legacy MD5 or SHA-1 based MAC, or a non-EtM (encrypt-and-MAC) UMAC variant: hmac-md5, hmac-md5-96, hmac-sha1, hmac-sha1-96, umac-64@openssh.com, or umac-128@openssh.com (the plain, non-EtM forms).

## Why it matters
The non-EtM variants compute the MAC over the plaintext, leaking information to an on-path attacker, and MD5 and SHA-1 MACs are legacy and no longer recommended.

## How to fix
- Restrict `MACs` in `sshd_config` and client config to EtM or AEAD MACs such as umac-128-etm@openssh.com or hmac-sha2-256-etm@openssh.com.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SSH_WEAK_MAC must not be reported.
