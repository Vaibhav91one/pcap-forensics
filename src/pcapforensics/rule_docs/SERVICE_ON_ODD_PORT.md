# SERVICE_ON_ODD_PORT

## What it means
An unencrypted ftp, telnet, ntp, smtp, ldap, mysql or redis flow where both ports are 1024 or higher and neither is a port that the protocol normally uses. TFTP is never reported, because its transfers run on ephemeral ports by design.

## Why it matters
A service on a non-standard port has no encryption layer detected and may bypass port-based allow or deny policy, creating a bypass surface.

## How to fix
- Confirm the service is intended on that port; if so, wrap it in TLS and firewall the port to the expected peers.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SERVICE_ON_ODD_PORT must not be reported.
