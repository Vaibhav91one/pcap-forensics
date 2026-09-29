#!/usr/bin/env bash
# Body of the pcap-doctor GitHub Action (action.yml): analyze each capture, and when the pull request's base
# commit has the same file, report and gate only the findings that are new since it (--baseline).
#
# Local run: PCAP_DOCTOR=.venv/bin/pcap-doctor CAPTURES='tests/fixtures/*.pcap' BASE_SHA=HEAD~1 scripts/pcap-doctor-action.sh
# Env: CAPTURES (bash globstar patterns, space separated), FAIL_ON (default high), BASE_SHA (optional),
#      OUT (default ./pcap-doctor-out), PCAP_DOCTOR (command, default pcap-doctor).
# ponytail: paths with spaces are not supported by the space-separated CAPTURES list.
set -uo pipefail
shopt -s globstar nullglob

read -ra pd <<< "${PCAP_DOCTOR:-pcap-doctor}"
out=${OUT:-pcap-doctor-out}
fail_on=${FAIL_ON:-high}
base=${BASE_SHA:-}
mkdir -p "$out/runs" "$out/sarif"
summary="$out/summary.md"
{
  echo "<!-- pcap-doctor -->"
  echo "### pcap-doctor"
  echo
  echo "| capture | new findings | findings | score |"
  echo "|---|---|---|---|"
} > "$summary"

if [ -n "$base" ] && ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$base" >/dev/null 2>&1 || echo "::warning::cannot fetch base $base; every finding counts as new"
fi

status=0
checked=0
# shellcheck disable=SC2086  # CAPTURES is a list of glob patterns: word splitting and globbing are the point
for cap in $CAPTURES; do
  checked=$((checked + 1))
  slug=$(printf '%s' "$cap" | tr '/ ' '__')
  run="$out/runs/$slug"
  mkdir -p "$run"
  baseline=()
  if [ -n "$base" ] && git cat-file -e "$base:$cap" 2>/dev/null; then
    git show "$base:$cap" > "$run/base-$(basename "$cap")"
    if "${pd[@]}" analyze "$run/base-$(basename "$cap")" -o "$run/base" -q --no-handoff; [ $? -le 1 ]; then
      baseline=(--baseline "$run/base/report.json")
    fi
  fi
  "${pd[@]}" analyze "$cap" -o "$run/head" -q --no-handoff --fail-on "$fail_on" \
    --json-out "$run/head.json" --sarif "$out/sarif/$slug.sarif" ${baseline[@]+"${baseline[@]}"}
  rc=$?
  if [ "$rc" -ge 2 ]; then
    status=2
    echo "| \`$cap\` | error (exit $rc) | | |" >> "$summary"
    continue
  fi
  [ "$rc" -eq 1 ] && [ "$status" -eq 0 ] && status=1
  python3 - "$run/head.json" "$cap" "$rc" >> "$summary" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
total = len(env["report"]["findings"])
new = len(env["new_findings"]) if "new_findings" in env else total
flag = " :x:" if sys.argv[3] == "1" else ""
print(f"| `{sys.argv[2]}` | {new}{flag} | {total} | {env['score']} {env['label']} |")
PY
done

if [ "$checked" -eq 0 ]; then
  echo "No capture matched \`$CAPTURES\`." >> "$summary"
else
  echo >> "$summary"
  echo "New = not in the base branch's copy of the capture. Gate: \`--fail-on $fail_on\`." >> "$summary"
fi

# One SARIF run per upload: GitHub code scanning rejects several runs with the same tool and category.
python3 - "$out/sarif" "$out/pcap-doctor.sarif" <<'PY'
import json, pathlib, sys
docs = [json.loads(p.read_text()) for p in sorted(pathlib.Path(sys.argv[1]).glob("*.sarif"))]
if docs:
    run = docs[0]["runs"][0]
    rules, results = {}, []
    for doc in docs:
        r = doc["runs"][0]
        for rule in r["tool"]["driver"]["rules"]:
            rules.setdefault(rule["id"], rule)
        results += r["results"]
    order = sorted(rules)
    run["tool"]["driver"]["rules"] = [rules[i] for i in order]
    for res in results:
        res["ruleIndex"] = order.index(res["ruleId"])
    run["results"] = results
    pathlib.Path(sys.argv[2]).write_text(json.dumps(docs[0], indent=2) + "\n")
PY

[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$summary" >> "$GITHUB_STEP_SUMMARY"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "summary=$summary" >> "$GITHUB_OUTPUT"
  [ -f "$out/pcap-doctor.sarif" ] && echo "sarif=$out/pcap-doctor.sarif" >> "$GITHUB_OUTPUT"
fi
cat "$summary"
exit "$status"
