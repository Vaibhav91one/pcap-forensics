# The real-world stress corpus

`pcap-doctor` is stress-tested against real firmware images and real captures, not only against the
synthetic fixtures under `tests/fixtures/`. This directory holds that corpus.

## What is committed, and what is not

Committed: `manifest.json` -- every artefact, where it came from, its licence, its size.

Not committed: `blobs/` (244 MB of firmware, 4 MB of captures) and `reports/` (regenerated on
every sweep). Both are rebuilt from the manifest by:

```bash
python scripts/corpus_manifest.py      # refresh the manifest from the live sources
python scripts/corpus_fetch.py         # download the blobs, verify SHA-256
python scripts/corpus_carve.py         # carve the root filesystem out of each image
python scripts/corpus_sweep.py --kind capture --sweep analyze
python scripts/corpus_sweep.py --kind firmware --sweep keys-scan
```

## What is in it

| | count | what |
|---|---|---|
| firmware | 42 | real OpenWrt sysupgrade images, six per release, 17.01.7 through 24.10.0, spanning ramips / ath79 / lantiq / brcm63xx / ipq40xx / mediatek / realtek targets. Real consumer devices: tp-link Archer C20i, TL-MR10U, TL-MR6400, Ubiquiti Air Gateway Pro, ZyXEL NBG6616 and A4001N1, Vodafone EasyBox 88388, Netgear R7000/R7800, ASUS MAP-AC2200, Check Point L-50, Cisco ON100. |
| captures | 219 | the whole `test/captures` directory of the wireshark project: real dissector input, including deliberately degenerate files (`empty.pcap`, a 101-byte frame, `http-ooo-fuzzed.pcapng`, fuzzed DTLS and DTLSv6 captures). |
| carved | 42 | every firmware image yielded a SquashFS root; 47,941 files extracted in total. |

## Policy

Published vendor downloads and public repositories only. No capture of anyone else's traffic, no
private key material of a third party, no exploit payload. Every blob has a `PROVENANCE.json` with
its URL, SHA-256, byte count and fetch time, so any finding that depends on a corpus artefact can be
traced back to the exact bytes.

## Why the carving is hand-rolled

The PyPI `binwalk` distribution is a stub that cannot be imported; there is no importable release.
Rather than vendor a third-party unpacker into a security tool's test corpus, `scripts/corpus_carve.py`
parses the SquashFS superblock itself. This also fixes a real trap: `file` misidentifies every image
in this corpus as jffs2, because the kernel partition ahead of the root filesystem is JFFS2-packed,
so the first magic byte in the file is never the root filesystem.

## What the sweeps measure

`scripts/corpus_sweep.py` records evidence; it asserts nothing by itself. A result is a defect when
the tool crashed, exited with an unexplained code, wrote no report, emitted a note about a dropped
tshark field or preference, cited frame 0, or -- for `keys scan` -- missed private-key PEM material
that a brute-force byte scan found in a text file on the same filesystem.

The last of those is the one that matters: a firmware audit that silently misses the key an attacker
would use is worse than no audit. The oracle deliberately skips binaries, because every mbedTLS build
carries compiled-in PEM self-test vectors inside `libmbedcrypto.so` that are not device keys.
