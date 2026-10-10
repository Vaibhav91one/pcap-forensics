# SMB_REMOTE_EXEC_PIPE

## What it means
A named pipe or service used for remote execution (svcctl, atsvc, PSEXESVC, winreg, remcom) was opened over SMB.

## Why it matters
PsExec, smbexec and atexec create and start services or scheduled tasks on the remote host through these pipes.

## How to fix
- Identify the source host and account.
- Block SMB between workstations; restrict remote service creation.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SMB_REMOTE_EXEC_PIPE must no longer be reported.
