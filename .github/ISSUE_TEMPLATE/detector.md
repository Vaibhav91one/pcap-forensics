---
name: Detector
about: Add a detector (one check, one file, one claim)
title: "detector: "
labels: detector
assignees: ''
---

**Which detector file**

`src/pcap_doctor/detectors/<name>.py` — new or existing.

**What it detects**

One sentence, in the words an analyst would use. Not "analyzes X" — "flags when Y".

**Why it matters**

What is the consequence if the condition is true and the tool is right?

**Input that reproduces it**

- capture: `<path or how to build it>`
- observable: `<the exact frame, field, or shape>`
- expected output:

```
<one line: the finding code, severity, confidence>
```

**Fields it needs from CaptureIndex**

| Field | Type | Example value | Already present? |
|---|---|---|---|
| `index.…` | | | yes / no (file an issue if no) |

**Fixture**

- [ ] added to `scripts/make_fixtures.py` and regenerated (`make fixtures`)
- [ ] deterministic (no randomness, no clock, no network)
- [ ] negative case too: a fixture where this must stay silent

**Checklist (AGENTS.md §3)**

- [ ] pure `detect(index) -> list[Finding]`, no I/O
- [ ] stable `code` and `scope`; ids stable across runs
- [ ] every finding has frame-numbered evidence with a non-empty value
- [ ] every finding has a `remediation`, plus references where a standard applies
- [ ] unknown input yields a finding or a note, never a silent pass
- [ ] no secret material can reach an artifact
- [ ] tests assert on codes, not prose
- [ ] README detector table has its row
- [ ] `make verify` green, `pcap-doctor doctor` passes
