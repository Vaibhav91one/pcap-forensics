# TLS_KEY_IN_FIRMWARE

## What it means
The certificate presented on this TLS session has the same public key as a private key found in the firmware image you passed to `--firmware` (matched by SPKI fingerprint, `sha256(DER public key)[:16]`). The private key that authenticates and protects this channel ships inside the device image.

## Why it matters
Anyone who has the firmware — it is usually downloadable — holds this private key. They can passively decrypt the channel (and, as a man-in-the-middle, actively tamper with it) on **every** device that ships the same image. Forward secrecy does not help: the attacker impersonates the server or decrypts recorded RSA-key-exchange sessions directly. A single shared, extractable key turns a per-device secret into a fleet-wide skeleton key.

## How to fix
- Provision a **unique** key pair per device (or at least per fleet), generated on first boot or at manufacture, instead of baking one private key into the image.
- Rotate the exposed key immediately and revoke its certificate.
- Keep private keys out of the shipped filesystem entirely; use a secure element or TPM where available.

## How to verify
Re-extract the current firmware and run `pcap-doctor analyze <capture> --firmware <extracted-tree>`; once each device has its own key, no session's certificate fingerprint matches a firmware key and TLS_KEY_IN_FIRMWARE is no longer reported.
