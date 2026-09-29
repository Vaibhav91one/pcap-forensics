---
name: Core change
about: Change models.py, index.py, tshark.py, data_ciphers.py or a renderer
title: "core: "
labels: core
assignees: ''
---

Core changes are a **merge event**, not a parallel one (`docs/subagent-playbook.md`).

**What changes**

Paths: `models.py` / `index.py` / `tshark.py` / `data_ciphers.py` / `certificates.py` / `render/*`

**Does `report.json`'s schema change?**

- [ ] no — additive only, `schema_version` unchanged
- [ ] yes, additive — bump minor
- [ ] yes, breaking — bump major, and list the migration in the issue

**If a new field is proposed**

| Field | Type | Example from a real capture | Read by |
|---|---|---|---|
| | | | |

**Which detectors are blocked without it**

**Migration / rollout**

- [ ] tests updated or added
- [ ] `docs/` updated (tshark-fields, severity-model, cipher-policy as applicable)
- [ ] `make verify` green
- [ ] agents holding open branches told to rebase
