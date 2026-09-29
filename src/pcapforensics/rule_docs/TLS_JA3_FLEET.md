# TLS_JA3_FLEET

## What it means
One client TLS fingerprint (JA3) was observed against at least 3 distinct servers across at least 5 sessions.

## Why it matters
A single JA3 reused across many servers is either managed software (a fleet agent or SDK) or a scanner/malware with a hard-coded TLS stack. The fingerprint itself is not a defect, but it enables clustering and attribution.

## How to fix
- Correlate the JA3 fingerprint with an asset inventory; add the fingerprint to an allow or deny policy if it is unexpected.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; TLS_JA3_FLEET must not be reported if the reuse is resolved or explained.
