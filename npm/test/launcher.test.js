// The npm launcher forwards to uvx (or pipx) pinned to its own version, and forwards the exit code (issue #51).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { version } = require("../package.json");

const LAUNCHER = path.join(__dirname, "..", "bin", "pcap-doctor.js");
const skip = process.platform === "win32" ? "fake runners are shell scripts" : false;

function fakeRunner(dir, name, exitCode) {
  const log = path.join(dir, `${name}.argv`);
  fs.writeFileSync(path.join(dir, name), `#!/bin/sh\nprintf '%s\\n' "$@" > '${log}'\nexit ${exitCode}\n`, { mode: 0o755 });
  return log;
}

function run(dir, args) {
  return spawnSync(process.execPath, [LAUNCHER, ...args], { env: { PATH: dir }, encoding: "utf8" });
}

test("uses uvx pinned to the package version and forwards the exit code", { skip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-doctor-"));
  const log = fakeRunner(dir, "uvx", 3);
  const result = run(dir, ["analyze", "x.pcap", "--fail-on", "high"]);
  assert.strictEqual(result.status, 3);
  assert.deepStrictEqual(fs.readFileSync(log, "utf8").trim().split("\n"), [
    "--from", `pcap-doctor==${version}`, "pcap-doctor", "analyze", "x.pcap", "--fail-on", "high",
  ]);
});

test("falls back to pipx when uvx is missing", { skip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-doctor-"));
  const log = fakeRunner(dir, "pipx", 0);
  const result = run(dir, ["--version"]);
  assert.strictEqual(result.status, 0);
  assert.deepStrictEqual(fs.readFileSync(log, "utf8").trim().split("\n"), [
    "run", "--spec", `pcap-doctor==${version}`, "pcap-doctor", "--version",
  ]);
});

test("explains what to install and exits 127 when neither runner exists", { skip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-doctor-"));
  const result = run(dir, ["--version"]);
  assert.strictEqual(result.status, 127);
  assert.match(result.stderr, /uv .* or pipx/);
});
