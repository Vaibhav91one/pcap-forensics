# Real key material with known properties: the ground truth for keys scan

`scripts/corpus_fetch.py` downloads blobs named by `corpus/manifest.json`. Each **keymaterial**
entry may carry an `expect` block: what `pcap-doctor keys scan` is *supposed* to report for that
file. The truth is known by construction -- these are the upstream projects' own test vectors, and
`openssl test/certs/` names them for what they are (`ee-key-1024.pem` is a 1024-bit key,
`ca-expired.pem` is expired).

`scripts/corpus_expect.py` lays the files out as trees, runs `keys scan` on each, and compares.
Any disagreement is a defect with a precise expected/actual, which is a far stronger signal than
"did it crash".

Three groups:

* **known-weak** -- 768- and 1024-bit RSA keys and certs. Expected: `weak-key-{bits}bit`.
* **known-expired** -- certs whose notAfter is in the past. Expected: `expired`.
* **key-and-cert** -- a private key and the certificate that carries its public half, in one tree.
  Expected: `private-key-for-a-shipped-cert` on the key and `private-key-present` on the cert.
  This is the finding that matters most in a firmware audit, and the stock OpenWrt corpus cannot
  produce it: those images ship no device keys at all, because dropbear generates host keys on
  first boot.
