# SSH_TERRAPIN_EXPOSED

## What it means
The SSH session offered chacha20-poly1305@openssh.com or a CBC cipher with a non-EtM MAC, and both peers did not offer strict key exchange.

## Why it matters
Without strict key exchange, a man-in-the-middle can drop messages at the start of the secure channel and downgrade extension negotiation, which is the Terrapin attack (CVE-2023-48795).

## How to fix
- Upgrade both ends to an SSH implementation with strict key exchange (OpenSSH 9.6+).
- Otherwise disable chacha20-poly1305 and EtM MACs paired with CBC ciphers.

## How to verify
Upgrade and re-capture, then run `pcap-doctor analyze <capture>`; SSH_TERRAPIN_EXPOSED must not be reported.
