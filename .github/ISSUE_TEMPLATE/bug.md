---
name: Bug
about: Something the analyzer gets wrong, or cannot run at all
title: "bug: "
labels: bug
assignees: ''
---

**What happened**

**What it should have done**

**Reproduce**

```bash
pf analyze <capture> --out /tmp/x --no-cache
```

**Wrong output, verbatim**

```
<paste the finding, the note, or the traceback -- exactly as printed>
```

**Ground truth**

How you know it is wrong. `tshark -r <capture> -Y '<filter>' -T fields -e <field>` output is ideal.

- [ ] `tshark` version: `pf doctor`
- [ ] capture sha256: `pf analyze <capture> | head -5`
- [ ] cache cleared or `--no-cache` used

**Scope**

- [ ] parser/index (core-owned)
- [ ] a detector
- [ ] rendering
- [ ] tshark field drift

**Suggested location**

File and function, if you know it. If this is a schema gap, propose the field rather than working
around it in a detector: `AGENTS.md` §1.
