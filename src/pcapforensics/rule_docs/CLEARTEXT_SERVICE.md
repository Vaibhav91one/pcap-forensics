# CLEARTEXT_SERVICE

## What it means
A sensitive application service (ftp, telnet, ldap, redis, mysql, or similar) was observed over a flow with no encryption layer.

## Why it matters
The protocol transmits commands, queries, and credentials without confidentiality; ftp, telnet, ldap, redis, and mysql routinely carry live credentials, while other protocols are a lower but still real exposure.

## How to fix
- Move to the encrypted variant: SFTP or FTPS, LDAPS, TLS-wrapped Redis and MySQL, and SSH instead of Telnet.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; CLEARTEXT_SERVICE must not be reported.
