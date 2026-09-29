#!/usr/bin/env bash
# Download the public sample captures used by tests/test_corpus.py.
#
# These come from the Wireshark project's own test suite (BSD-2-Clause) on
# GitHub. They are the ground truth the detector tests are checked against:
# every assertion in test_corpus.py was verified by hand against tshark -V.
set -euo pipefail

BASE="https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures"
DIR="$(cd "$(dirname "$0")/.." && pwd)/captures"
mkdir -p "$DIR"

CAPTURES=(
  tls13-rfc8446.pcap
  tls12-aes128ccm.pcap
  tls12-aes256gcm.pcap
  tls12-chacha20poly1305.pcap
  tls-renegotiation.pcap
  retrans-tls.pcap
  snakeoil-dtls.pcap
  dtls12-aes128ccm8.pcap
  quic-with-secrets.pcapng
  sip.pcapng
  sip-rtp.pcapng
  dns_port.pcap
  dns-mdns.pcap
  ntp.pcap
  tftp.pcap
)

for name in "${CAPTURES[@]}"; do
  if [ -s "$DIR/$name" ]; then
    echo "  have $name"
    continue
  fi
  printf '  fetch %-32s' "$name"
  if curl -fsSL -o "$DIR/$name" "$BASE/$name"; then
    echo "ok"
  else
    echo "FAILED"
    rm -f "$DIR/$name"
  fi
done

echo
echo "corpus:"
capinfos -c -M "$DIR"/*.pcap "$DIR"/*.pcapng 2>/dev/null | tail -n +2 || ls -la "$DIR"
