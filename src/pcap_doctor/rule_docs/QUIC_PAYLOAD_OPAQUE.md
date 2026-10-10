# QUIC_PAYLOAD_OPAQUE

## What it means
A QUIC flow was observed whose payload cannot be decrypted without keying material, because QUIC encrypts its headers and application data.

## Why it matters
Without the keying material, the payload and inner HTTP/3 cannot be inspected; this note stays for whatever QUIC traffic is present, and that is expected.

## How to fix
- To inspect payload, capture with the SSLKEYLOGFILE variable set on the client and open the capture in Wireshark. pcap-doctor does not accept a keylog.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; this note remains for any QUIC flow that is present without keying material.
