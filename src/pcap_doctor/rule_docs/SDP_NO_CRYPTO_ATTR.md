# SDP_NO_CRYPTO_ATTR

## What it means
An SDP offer or advertisement carrying audio or video media lines has no SRTP crypto attribute (an `a=crypto` line) that negotiates a recognised SRTP suite.

## Why it matters
Without an SRTP crypto attribute, SRTP cannot be negotiated, so any RTP stream on the same flow is eavesdroppable in cleartext.

## How to fix
- Advertise SDES-SRTP (`a=crypto`) or DTLS-SRTP in every SDP offer.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; SDP_NO_CRYPTO_ATTR must not be reported.
