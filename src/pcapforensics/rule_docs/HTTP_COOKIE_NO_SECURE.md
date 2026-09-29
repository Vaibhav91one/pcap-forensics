# HTTP_COOKIE_NO_SECURE

## What it means
A server set cookie(s) without the Secure flag over a cleartext HTTP flow with a non-error status.

## Why it matters
Cookies without Secure travel in the clear on every plaintext HTTP request and leak to any on-path observer, including later requests to the same host over cleartext.

## How to fix
- Set Secure, HttpOnly and SameSite on every session cookie and serve the site over HTTPS only.

## How to verify
Capture the same traffic again and run `pcap-doctor analyze <capture>`; HTTP_COOKIE_NO_SECURE must not be reported.
