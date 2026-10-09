"""``mcp``: serve the CLI as MCP tools over stdio (newline-delimited JSON-RPC 2.0, stdlib only).

Every tool runs the real CLI in a subprocess (``python -m pcapforensics.cli ...``) and returns its stdout
unchanged, so ``analyze`` is byte-identical to ``pcap-doctor analyze --json`` for the same arguments
(doctor-contract section 7). A tool is one row of ``TOOLS``; a new CLI command needs one row, not a handler.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from importlib.metadata import version
from typing import Any

import typer

PROTOCOL = "2025-06-18"
# ponytail: one subprocess per call, so a call costs an interpreter start; keep a worker pool if that bites
TIMEOUT = 900


@dataclass(frozen=True)
class Param:
    name: str
    kind: str  # "arg" positional | "flag" boolean | "opt" value | "multi" repeated value | "int" value
    flag: str = ""  # CLI spelling for flag/opt/multi/int
    help: str = ""
    required: bool = False


@dataclass(frozen=True)
class Tool:
    name: str
    help: str
    argv: tuple[str, ...]  # fixed words, including flags every call needs
    params: tuple[Param, ...] = ()
    ok: tuple[int, ...] = (0,)  # exit codes that are a result, not an error


def _p(name: str, kind: str, flag: str = "", help: str = "", required: bool = False) -> Param:
    return Param(name, kind, flag or "--" + name.replace("_", "-"), help, required)


TOOLS: tuple[Tool, ...] = (
    Tool(
        "analyze",
        "Analyze a pcap/pcapng and return the doctor/1 JSON envelope (same as `pcap-doctor analyze --json`). "
        "Exit codes 0/1/3 are results: see `exit_code` in the envelope.",
        ("analyze", "--json", "--no-handoff"),
        (
            _p("path", "arg", help="pcap or pcapng file", required=True),
            _p("out", "opt", help="output directory for the report files"),
            _p("only", "multi", help="run only these detector ids"),
            _p("category", "multi", help="keep only findings in these categories"),
            _p("min_severity", "opt", help="drop findings below this severity"),
            _p("fail_on", "opt", help="none|critical|high|medium|low|info"),
            _p("baseline", "opt", help="earlier --json envelope: only new findings gate (exit 3)"),
            _p("sarif", "opt", help="also write SARIF 2.1.0 to this file"),
            _p("config", "opt", help="config file"),
            _p("profile", "opt", help="preset, e.g. ota"),
            _p("no_cache", "flag", help="ignore the tshark pass cache"),
            _p("tls_key", "multi", help="TLS private key (PEM) to decrypt your own capture"),
            _p("tls_key_password", "opt", help="passphrase for tls_key"),
            _p("keys_from", "opt", help="extracted-firmware tree to load PEM private keys from"),
            _p("firmware", "multi", help="extracted-firmware tree to correlate server keys against"),
            _p("keylog", "opt", help="TLS key-log file (SSLKEYLOGFILE format)"),
            _p("psk", "opt", help="TLS/DTLS pre-shared key, hex"),
        ),
        ok=(0, 1, 3),
    ),
    Tool(
        "why",
        "Explain one finding from a report.json: facts, evidence, fix, rule text (or a fix prompt).",
        ("why",),
        (
            _p("query", "arg", help="finding id, id/hash/fingerprint prefix, or a frame number", required=True),
            _p("report", "opt", help="report.json path (default: the one *.pf-report in the cwd)"),
            _p("prompt", "flag", help="print a fix prompt for a coding agent instead"),
        ),
    ),
    Tool(
        "rules_list",
        "List the finding codes pcap-doctor can raise.",
        ("rules", "list"),
        (_p("category", "multi", help="only these categories"),),
    ),
    Tool(
        "rules_explain",
        "Explain one finding code.",
        ("rules", "explain"),
        (_p("code", "arg", help="finding code, e.g. TLS_VERSION_DEPRECATED", required=True),),
    ),
    Tool(
        "keys_scan",
        "Inventory key material in an extracted firmware tree and flag the dangerous parts (JSON).",
        ("keys", "scan", "--json"),
        (
            _p("directory", "arg", help="extracted firmware filesystem tree", required=True),
            _p("out", "opt", help="copy the private keys here for analyze keys_from"),
        ),
        ok=(0, 1),
    ),
    Tool(
        "flows",
        "List the conversations in a capture.",
        ("flows",),
        (_p("pcap", "arg", help="pcap or pcapng file", required=True), _p("top", "int", help="how many flows")),
    ),
    Tool("ciphers", "Show the TLS cipher suites negotiated in a capture.", ("ciphers",),
         (_p("pcap", "arg", help="pcap or pcapng file", required=True),)),
    Tool("detectors", "List the detectors.", ("detectors",)),
    Tool("suites", "List the cipher-suite policy table.", ("suites",)),
    Tool("doctor", "Check that tshark and the environment are usable.", ("doctor",)),
    Tool("schema", "Print the machine-output schema (doctor/1) and the report.json schema version.", ("schema",)),
)
BY_NAME = {t.name: t for t in TOOLS}


def schema_of(tool: Tool) -> dict[str, Any]:
    props: dict[str, Any] = {}
    for p in tool.params:
        kind: dict[str, dict[str, Any]] = {"flag": {"type": "boolean"}, "int": {"type": "integer"}, "multi": {"type": "array", "items": {"type": "string"}}}
        props[p.name] = {**kind.get(p.kind, {"type": "string"}), "description": p.help}
    return {
        "type": "object",
        "properties": props,
        "required": [p.name for p in tool.params if p.required],
        "additionalProperties": False,
    }


def argv_of(tool: Tool, args: dict[str, Any]) -> list[str]:
    """CLI argv for a call; ValueError for an unknown or missing argument."""
    known = {p.name for p in tool.params}
    if extra := sorted(set(args) - known):
        raise ValueError(f"unknown argument(s): {', '.join(extra)}")
    argv = list(tool.argv)
    positional: list[str] = []
    for p in tool.params:
        value = args.get(p.name)
        if value is None or value is False:
            if p.required:
                raise ValueError(f"missing argument: {p.name}")
            continue
        if p.kind == "arg":
            positional.append(str(value))
        elif p.kind == "flag":
            argv.append(p.flag)
        elif p.kind == "multi":
            items = value if isinstance(value, list) else [value]
            for item in items:
                argv += [p.flag, str(item)]
        else:
            argv += [p.flag, str(value)]
    # "--" keeps a path that starts with "-" from being read as an option
    return argv + (["--", *positional] if positional else [])


def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    tool = BY_NAME.get(name)
    if tool is None:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
    try:
        argv = argv_of(tool, args)
        proc = subprocess.run(
            [sys.executable, "-m", "pcapforensics.cli", *argv], capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (ValueError, subprocess.TimeoutExpired) as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    if proc.returncode in tool.ok:
        return {"content": [{"type": "text", "text": proc.stdout}], "isError": False}
    text = f"exit {proc.returncode}\n{proc.stdout}{proc.stderr}"
    return {"content": [{"type": "text", "text": text}], "isError": True}


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    """One JSON-RPC message in, the reply out (None for a notification)."""
    method, ident, params = message.get("method"), message.get("id"), message.get("params") or {}
    if ident is None:
        return None  # notifications (initialized, cancelled, ...) get no reply

    def ok(result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": ident, "result": result}

    if method == "initialize":
        return ok({
            "protocolVersion": params.get("protocolVersion") or PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "pcap-doctor", "version": version("pcap-doctor")},
        })
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": [{"name": t.name, "description": t.help, "inputSchema": schema_of(t)} for t in TOOLS]})
    if method == "tools/call":
        return ok(call(str(params.get("name")), params.get("arguments") or {}))
    return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve(stdin: Any = None, stdout: Any = None) -> None:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            reply = handle(message) if isinstance(message, dict) else None
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def mcp() -> None:
    """Serve pcap-doctor as MCP tools over stdio (for Claude Code, Cursor, Codex, ...)."""
    serve()


def register(app: typer.Typer) -> None:
    app.command("mcp")(mcp)
