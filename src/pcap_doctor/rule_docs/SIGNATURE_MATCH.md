# SIGNATURE_MATCH

## What it means
A rule you supplied with `--signatures` (Suricata syntax or a Zeek `.sig` file) matched traffic in the capture. The finding names the rule's `sid` and message, the flow, and the frame whose payload completed the match.

## Why it matters
The rule encodes something you decided to look for: a known-bad pattern, a policy violation or an indicator of compromise. A match means that traffic is present in this capture.

## How to fix
- Treat it as the rule's author intended: investigate the flow, the hosts and the frame cited.
- If the rule is a false positive, tighten its content or pcre, or remove it.

## How to verify
Re-run `pcap-doctor analyze <capture> --signatures <rules>` after the fix; the `sid` must no longer match.
