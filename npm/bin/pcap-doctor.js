#!/usr/bin/env node
// `npx pcap-doctor ...` runs the Python CLI of the same version from PyPI (issue #51).
// No dependencies: uvx first, pipx second; tshark must still be installed separately.
"use strict";

const { spawnSync } = require("node:child_process");
const { version } = require("../package.json");

const spec = `pcap-doctor==${version}`;
const args = process.argv.slice(2);
const runners = [
  ["uvx", ["--from", spec, "pcap-doctor", ...args]],
  ["pipx", ["run", "--spec", spec, "pcap-doctor", ...args]],
];

for (const [command, argv] of runners) {
  const result = spawnSync(command, argv, { stdio: "inherit" });
  if (result.error && result.error.code === "ENOENT") continue;
  if (result.error) {
    console.error(`pcap-doctor: could not run ${command}: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

console.error(
  "pcap-doctor needs uv (https://docs.astral.sh/uv/) or pipx to run, and tshark (Wireshark) to analyze captures.",
);
process.exit(127);
