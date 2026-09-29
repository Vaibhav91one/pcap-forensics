# CLEARTEXT_CREDENTIAL

## What it means
A credential crossed the network unencrypted: an SNMP community string, an LDAP simple-bind password, a MySQL query's text, an FTP PASS argument, or a Telnet password (for Telnet only the password length and its frame are recorded, never the value itself).

## Why it matters
Anyone on-path can capture the credential. Treat every exposed credential as compromised.

## How to fix
- Rotate the exposed credential immediately.
- Move to encrypted transports with authentication: SNMPv3, LDAPS or LDAP StartTLS, MySQL over TLS, SFTP or FTPS, and SSH instead of Telnet.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; CLEARTEXT_CREDENTIAL must not be reported.
