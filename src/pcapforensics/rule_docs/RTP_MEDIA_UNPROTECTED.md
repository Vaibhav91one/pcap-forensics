# RTP_MEDIA_UNPROTECTED

## What it means
An RTP stream was observed on a flow whose SIP media offers contain no SRTP crypto attribute, so the media was not negotiated for encryption.

## Why it matters
Without SRTP, RTP payload (voice or video) is directly recoverable by any on-path observer. Sessions that carry a large volume of media (over 20000 bytes or longer than a minute) are the most exposed.

## How to fix
- Require SRTP (SDES or DTLS-SRTP) for all media; consider SIP-TLS signalling too.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; RTP_MEDIA_UNPROTECTED must not be reported.
