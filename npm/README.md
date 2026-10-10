# pcap-doctor

Offline doctor for `.pcap` and `.pcapng` captures, built for IoT, OTA and network-device traffic.
One command gives a 0-100 health score, findings grouped by category (weak TLS/SSH crypto, cleartext
credentials, plain HTTP and firmware downloads, DNS, VoIP exposure), and a report you can paste into a
ticket. Every finding points at a frame number you can open in Wireshark.

```bash
npx pcap-doctor analyze traffic.pcap                   # score, findings, report files
npx pcap-doctor analyze traffic.pcap --fail-on high    # CI gate: exit 1 on a high or worse finding
npx pcap-doctor why 4                                  # explain the findings that cite frame 4
npx pcap-doctor ci install                             # GitHub Actions workflow for pull requests
```

In a terminal the scan ends on an interactive screen: review the findings, copy a findings report,
add the GitHub Actions check, or hand a finding to Claude Code, Codex or Cursor with a fix prompt.

## What this npm package is

A tiny launcher with no dependencies. It runs the Python CLI of the **same version** from PyPI
through [`uvx`](https://docs.astral.sh/uv/) (or `pipx run` when uv is missing) and passes on its exit
code. You need:

- [uv](https://docs.astral.sh/uv/) or [pipx](https://pipx.pypa.io/), and
- [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html) on `PATH` (`brew install wireshark`,
  `sudo apt-get install -y tshark`).

Prefer Python directly? `uvx pcap-doctor …` or `pip install pcap-doctor`.

No telemetry, no network calls during analysis. Documentation, rule reference and changelog:
<https://github.com/doctor-labs/pcap-doctor>. MIT licensed.
