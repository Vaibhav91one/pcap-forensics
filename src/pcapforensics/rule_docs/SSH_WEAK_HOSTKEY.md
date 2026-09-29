# SSH_WEAK_HOSTKEY

## What it means
The SSH host-key algorithm list offered by either peer includes ssh-rsa, ssh-dss, or ssh-rsa-sha256@libssh.org.

## Why it matters
ssh-rsa and ssh-dss sign with SHA-1 and DSA keys are limited to 1024 bits, and the ssh-rsa-sha256@libssh.org variant is a non-standard name that some implementations reject.

## How to fix
- Restrict `HostKeyAlgorithms` in `sshd_config` and client config to rsa-sha2-256/512, ecdsa-sha2-nistp256/384/521, or ssh-ed25519.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SSH_WEAK_HOSTKEY must not be reported.
