# TLS_LEGACY_RECORD_VERSION

Severity ``info``, confidence ``medium`` (``#150``, decided in ``docs/severity-model.md``). It fires as inventory, not as a
defect, and it is not suppressed: the genuine post-handshake case still has to be reported.

## What it means
A TLS or DTLS record in this session carries an older version (SSL 3.0, TLS 1.0, TLS 1.1, or DTLS
1.0) in its record-layer version field than the version the session negotiated.

## Why it matters
Only on a post-handshake application record. On a ClientHello the legacy field is a constant, not
an observation: RFC 8446 has a TLS 1.3 ClientHello put ``0x0301`` in the record layer and states the field
MUST be ignored in favour of ``supported_versions``, and RFC 5246 does the same for the first record of a
TLS 1.2 ClientHello. Where a peer instead honours the legacy field on data records, it downgrades
its own handling of them.

The detector cannot make that distinction. ``TlsSession.record_versions`` is a de-duplicated list of
version names — no frame number, no record content type — so a sentinel ClientHello and a
downgraded application record leave an identical index. That is why the confidence is ``medium``
rather than ``high``: the capture cannot say which record carried the value. Tracked as
[#157](https://github.com/doctor-labs/pcap-doctor/issues/157).

## How to fix
- Nothing, if the legacy version appears only on handshake records. That is the value the protocol
  mandates, and it is what ``tshark`` marks "this legacy_version field MUST be ignored".
- If it appears on an application-data record (content type 23), upgrade the peer stack so it only
  emits the negotiated version on data records.
- Read the record layer per record before filing anything. In the 219-capture corpus this rule
  fired 26 times in 17 captures and every one of those values was on a ClientHello.

## How to verify
Confirm the record that carried it, since the finding cannot:

```
    tshark -r <capture> -Y 'tls.record.content_type == 23 && tls.record.version < 0x0303' \
      -T fields -e frame.number -e tls.record.version
```

No output means no legacy version reached an application-data record and there is nothing to fix.
Output means the finding was real; confirm the same traffic with ``pcap-doctor analyze <capture>`` and check
that ``pcap-doctor why <id>`` reports it at ``info``.