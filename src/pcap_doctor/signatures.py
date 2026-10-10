"""A signature engine for user-supplied detections: a Suricata rule subset and Zeek signatures (issue #201).

Rules are matched against the payloads in the capture (``payload`` tshark pass). TCP payloads are appended per
direction to a stream buffer (capped at 1 MiB), so a pattern split across segments still matches; a rule fires at
most once per flow (and direction rule), at the frame whose payload completed the match.

Supported Suricata syntax (anything else makes the rule *skipped with a warning*, never silently approximated):
``alert|drop|reject|pass|log`` (all but ``pass`` report; a ``pass`` match silences the flow from then on), protocols
``tcp udp ip`` (``http`` and ``tls`` are treated as ``tcp``), address lists with CIDR/negation/``$VARS``, port
lists/ranges, ``->`` and ``<>``, and the options ``msg content (|hex|, !negation) nocase offset depth distance
within pcre dsize flow flags sid rev classtype priority reference metadata gid fast_pattern``.
Supported Zeek signature syntax: ``signature id { ip-proto ==|!= tcp|udp|icmp; src-ip/dst-ip ==|!= list;
src-port/dst-port ==|!= list; payload /regex/; event "msg" }``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from .index import CaptureIndex, first
from .models import flow_key
from .tshark import to_int

BUFFER_CAP = 1 << 20  # ponytail: one buffer per flow direction, capped; upgrade to an incremental matcher if captures need more
DEFAULT_VARS = {
    "HOME_NET": "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]",
    "EXTERNAL_NET": "!$HOME_NET",
    "HTTP_PORTS": "80",
    "HTTP_SERVERS": "$HOME_NET",
}
IGNORED = {"fast_pattern", "metadata", "reference", "classtype", "priority", "rev", "gid", "sid", "msg", "target",
           "threshold", "detection_filter", "noalert"}


class RuleError(ValueError):
    pass


@dataclass
class Content:
    pattern: bytes
    negate: bool = False
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass
class Rule:
    sid: str
    msg: str
    action: str = "alert"
    proto: str = "ip"
    src: list[tuple[bool, str]] = field(default_factory=list)  # (negated, spec); empty = any
    sport: list[tuple[bool, tuple[int, int]]] = field(default_factory=list)
    dst: list[tuple[bool, str]] = field(default_factory=list)
    dport: list[tuple[bool, tuple[int, int]]] = field(default_factory=list)
    bidirectional: bool = False
    contents: list[Content] = field(default_factory=list)
    pcre: list[tuple[re.Pattern[bytes], bool]] = field(default_factory=list)
    dsize: tuple[str, int, int] | None = None
    to_server: bool | None = None  # flow:to_server / to_client
    flags: str | None = None
    classtype: str = ""
    priority: int = 3
    rev: str = "1"
    text: str = ""

    def severity(self) -> str:
        return {1: "high", 2: "medium"}.get(self.priority, "low")


@dataclass
class SignatureHit:
    sid: str
    msg: str
    classtype: str
    priority: int
    rev: str
    flow_key: str
    frame: int
    src: str
    dst: str
    rule: str


# ---------------------------------------------------------------------------------------------- parsing
def _split_list(text: str) -> list[str]:
    """Split ``a,b,[c,d]`` on top-level commas."""
    items, depth, cur = [], 0, ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur)
    return [i.strip() for i in items]


def _expand(spec: str, variables: dict[str, str], depth: int = 0) -> str:
    if depth > 8:
        raise RuleError("variable expansion too deep")
    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in variables:
            raise RuleError(f"undefined variable ${name}")
        return _expand(variables[name], variables, depth + 1)
    return re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", sub, spec)


def _flatten_addrs(spec: str, negate: bool = False) -> list[tuple[bool, str]]:
    spec = spec.strip()
    if spec.startswith("!"):
        return _flatten_addrs(spec[1:], not negate)
    if spec.startswith("[") and spec.endswith("]"):
        out: list[tuple[bool, str]] = []
        for item in _split_list(spec[1:-1]):
            out += _flatten_addrs(item, negate)
        return out
    if spec.lower() == "any":
        return []
    try:
        ipaddress.ip_network(spec, strict=False)
    except ValueError as exc:
        raise RuleError(f"bad address {spec!r}") from exc
    return [(negate, spec)]


def _flatten_ports(spec: str, negate: bool = False) -> list[tuple[bool, tuple[int, int]]]:
    spec = spec.strip()
    if spec.startswith("!"):
        return _flatten_ports(spec[1:], not negate)
    if spec.startswith("[") and spec.endswith("]"):
        out: list[tuple[bool, tuple[int, int]]] = []
        for item in _split_list(spec[1:-1]):
            out += _flatten_ports(item, negate)
        return out
    if spec.lower() == "any":
        return []
    m = re.fullmatch(r"(\d*)(:?)(\d*)", spec)
    if not m or not (m.group(1) or m.group(3)):
        raise RuleError(f"bad port {spec!r}")
    lo = int(m.group(1)) if m.group(1) else 0
    hi = int(m.group(3)) if m.group(3) else 65535
    if not m.group(2):
        hi = lo
    return [(negate, (lo, hi))]


def _content_bytes(raw: str) -> bytes:
    out, i = b"", 0
    while i < len(raw):
        if raw[i] == "|":
            j = raw.find("|", i + 1)
            if j < 0:
                raise RuleError("unterminated |hex| in content")
            try:
                out += bytes.fromhex(raw[i + 1 : j].replace(" ", ""))
            except ValueError as exc:
                raise RuleError(f"bad hex in content: {raw[i:j + 1]}") from exc
            i = j + 1
        else:
            if raw[i] == "\\" and i + 1 < len(raw):
                i += 1
            out += raw[i].encode("latin-1", "replace")
            i += 1
    return out


def _options(body: str) -> list[tuple[str, str | None]]:
    """``key:value;`` pairs, honouring quotes and backslash escapes."""
    out, cur, quoted, esc = [], "", False, False
    for ch in body:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            cur += ch
            esc = True
        elif ch == '"':
            quoted = not quoted
            cur += ch
        elif ch == ";" and not quoted:
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    pairs = []
    for item in out:
        key, sep, value = item.partition(":")
        pairs.append((key.strip(), value.strip() if sep else None))
    return pairs


def _unquote(value: str | None) -> str:
    v = (value or "").strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


_HEADER = re.compile(r"^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$", re.S)


def parse_suricata(line: str, variables: dict[str, str]) -> Rule:
    m = _HEADER.match(line.strip())
    if not m:
        raise RuleError("not a rule: expected `action proto src sport -> dst dport (options)`")
    action, proto, src, sport, arrow, dst, dport, body = m.groups()
    if action not in ("alert", "drop", "reject", "pass", "log"):
        raise RuleError(f"unsupported action {action!r}")
    if proto in ("http", "tls", "ssh", "ftp", "smtp", "dns"):
        proto = "tcp" if proto != "dns" else "udp"
    if proto not in ("tcp", "udp", "ip"):
        raise RuleError(f"unsupported protocol {proto!r}")
    rule = Rule(sid="", msg="", action=action, proto=proto, bidirectional=arrow == "<>", text=line.strip())
    rule.src = _flatten_addrs(_expand(src, variables))
    rule.dst = _flatten_addrs(_expand(dst, variables))
    rule.sport = _flatten_ports(_expand(sport, variables))
    rule.dport = _flatten_ports(_expand(dport, variables))
    for key, value in _options(body):
        if key == "sid":
            rule.sid = (value or "").strip()
        elif key == "msg":
            rule.msg = _unquote(value)
        elif key == "rev":
            rule.rev = (value or "1").strip()
        elif key == "classtype":
            rule.classtype = (value or "").strip()
        elif key == "priority":
            rule.priority = to_int(value or "") or 3
        elif key == "content":
            negate = (value or "").lstrip().startswith("!")
            raw = _unquote((value or "").lstrip().removeprefix("!"))
            rule.contents.append(Content(_content_bytes(raw), negate))
        elif key in ("nocase", "offset", "depth", "distance", "within"):
            if not rule.contents:
                raise RuleError(f"`{key}` before any content")
            last = rule.contents[-1]
            if key == "nocase":
                last.nocase = True
            else:
                setattr(last, key, to_int(value or ""))
        elif key == "pcre":
            raw = _unquote((value or "").lstrip().removeprefix("!"))
            pm = re.fullmatch(r"/(.*)/([a-zA-Z]*)", raw, re.S)
            if not pm:
                raise RuleError("pcre must look like /pattern/flags")
            flags = 0
            for f in pm.group(2):
                if f in "ismx":
                    flags |= {"i": re.I, "s": re.S, "m": re.M, "x": re.X}[f]
                elif f not in "AR":
                    raise RuleError(f"unsupported pcre flag {f!r}")
            try:
                rule.pcre.append((re.compile(pm.group(1).encode("latin-1", "replace"), flags), (value or "").lstrip().startswith("!")))
            except re.error as exc:
                raise RuleError(f"bad pcre: {exc}") from exc
        elif key == "dsize":
            dm = re.fullmatch(r"\s*(<|>)?\s*(\d+)(?:\s*<>\s*(\d+))?\s*", value or "")
            if not dm:
                raise RuleError(f"bad dsize {value!r}")
            rule.dsize = (dm.group(1) or ("<>" if dm.group(3) else "="), int(dm.group(2)), int(dm.group(3) or dm.group(2)))
        elif key == "flow":
            for part in (value or "").split(","):
                part = part.strip()
                if part == "to_server" or part == "from_client":
                    rule.to_server = True
                elif part == "to_client" or part == "from_server":
                    rule.to_server = False
                elif part not in ("established", "stateless", "no_stream", "only_stream", "not_established"):
                    raise RuleError(f"unsupported flow option {part!r}")
        elif key == "flags":
            rule.flags = (value or "").split(",")[0].strip().upper()
        elif key in IGNORED:
            continue
        else:
            raise RuleError(f"unsupported keyword `{key}`")
    if not rule.sid:
        raise RuleError("rule has no sid")
    if not (rule.contents or rule.pcre or rule.dsize or rule.flags):
        raise RuleError("rule has nothing to match on (needs content, pcre, dsize or flags)")
    if not rule.msg:
        rule.msg = f"signature {rule.sid}"
    return rule


def parse_zeek(text: str, variables: dict[str, str]) -> list[Rule]:
    rules = []
    for m in re.finditer(r"signature\s+([\w-]+)\s*\{(.*?)\}", text, re.S):
        name, body = m.groups()
        rule = Rule(sid=name, msg=name, text=m.group(0).strip(), priority=2)
        for stmt in [s.strip() for s in body.split("\n") if s.strip()]:
            stmt = stmt.rstrip(";").strip()
            sm = re.fullmatch(r"([\w-]+)\s*(==|!=)?\s*(.*)", stmt, re.S)
            if not sm:
                raise RuleError(f"signature {name}: cannot read `{stmt}`")
            key, op, value = sm.groups()
            neg = op == "!="
            if key == "ip-proto":
                if neg or value.strip() not in ("tcp", "udp"):
                    raise RuleError(f"signature {name}: only `ip-proto == tcp|udp` is supported")
                rule.proto = value.strip()
            elif key in ("src-ip", "dst-ip"):
                addrs = _flatten_addrs("[" + _expand(value.replace(" ", ""), variables) + "]", neg)
                setattr(rule, "src" if key == "src-ip" else "dst", addrs)
            elif key in ("src-port", "dst-port"):
                ports = _flatten_ports("[" + _expand(value.replace(" ", ""), variables) + "]", neg)
                setattr(rule, "sport" if key == "src-port" else "dport", ports)
            elif key == "payload":
                pm = re.fullmatch(r"/(.*)/", value.strip(), re.S)
                if not pm:
                    raise RuleError(f"signature {name}: payload needs /regex/")
                try:
                    rule.pcre.append((re.compile(pm.group(1).encode("latin-1", "replace")), False))
                except re.error as exc:
                    raise RuleError(f"signature {name}: bad regex: {exc}") from exc
            elif key == "event":
                rule.msg = _unquote(value)
            else:
                raise RuleError(f"signature {name}: unsupported condition `{key}`")
        if not rule.pcre:
            raise RuleError(f"signature {name}: needs a payload /regex/")
        rules.append(rule)
    if not rules:
        raise RuleError("no `signature name { ... }` block found")
    return rules


def load_rules(paths: list[Path], variables: dict[str, str] | None = None) -> tuple[list[Rule], list[str]]:
    """Rules and warnings. ``.sig`` files are Zeek signatures, anything else Suricata rules. A bad rule is a warning."""
    merged = {**DEFAULT_VARS, **(variables or {})}
    rules: list[Rule] = []
    warnings: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".sig":
            try:
                rules += parse_zeek(text, merged)
            except RuleError as exc:
                warnings.append(f"{path.name}: {exc}")
            continue
        logical = re.sub(r"\\\n", "", text)
        for n, line in enumerate(logical.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rules.append(parse_suricata(line, merged))
            except RuleError as exc:
                warnings.append(f"{path.name}:{n}: skipped: {exc}")
    return rules, warnings


# ---------------------------------------------------------------------------------------------- matching
def _addr_ok(spec: list[tuple[bool, str]], ip: str) -> bool:
    if not spec:
        return True
    addr = ipaddress.ip_address(ip)
    positives = [s for s in spec if not s[0]]
    for negated, net in spec:
        if negated and addr in ipaddress.ip_network(net, strict=False):
            return False
    return not positives or any(addr in ipaddress.ip_network(n, strict=False) for _, n in positives)


def _port_ok(spec: list[tuple[bool, tuple[int, int]]], port: int) -> bool:
    if not spec:
        return True
    for negated, (lo, hi) in spec:
        if negated and lo <= port <= hi:
            return False
    positives = [s for s in spec if not s[0]]
    return not positives or any(lo <= port <= hi for _, (lo, hi) in positives)


def _header_ok(rule: Rule, proto: str, src: str, sp: int, dst: str, dp: int) -> bool:
    if rule.proto != "ip" and rule.proto != proto:
        return False

    def one(a: str, ap: int, b: str, bp: int) -> bool:
        return _addr_ok(rule.src, a) and _port_ok(rule.sport, ap) and _addr_ok(rule.dst, b) and _port_ok(rule.dport, bp)

    return one(src, sp, dst, dp) or (rule.bidirectional and one(dst, dp, src, sp))


_TCP_FLAGS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


def _flags_ok(want: str, have: int) -> bool:
    mask = 0
    for ch in want.replace("+", "").replace("*", "").replace("!", ""):
        mask |= _TCP_FLAGS.get(ch, 0)
    if want.startswith("!"):
        return not (have & mask)
    if want.endswith("*"):
        return bool(have & mask)
    if want.endswith("+"):
        return (have & mask) == mask
    return have == mask or (have & 0x3F) == mask


def _content_ok(buf: bytes, contents: list[Content]) -> bool:
    """Sequential content match: offset/depth are absolute, distance/within are relative to the previous hit."""
    cursor = 0
    for c in contents:
        hay = buf.lower() if c.nocase else buf
        needle = c.pattern.lower() if c.nocase else c.pattern
        if c.distance is not None or c.within is not None:
            start = cursor + (c.distance or 0)
            end = start + c.within if c.within is not None else len(hay)
        else:
            start = c.offset or 0
            end = start + c.depth if c.depth is not None else len(hay)
        pos = hay.find(needle, max(0, start), end)
        if c.negate:
            if pos >= 0:
                return False
            continue
        if pos < 0:
            return False
        cursor = pos + len(needle)
    return True


def _payload_ok(rule: Rule, packet: bytes, buf: bytes) -> bool:
    if rule.dsize:
        op, a, b = rule.dsize
        n = len(packet)
        if not ((op == "=" and n == a) or (op == "<" and n < a) or (op == ">" and n > a) or (op == "<>" and a < n < b)):
            return False
    if not _content_ok(buf, rule.contents):
        return False
    return all((rx.search(buf) is None) if neg else (rx.search(buf) is not None) for rx, neg in rule.pcre)


def match(index: CaptureIndex, rules: list[Rule]) -> list[SignatureHit]:
    """Run ``rules`` over the capture's payloads. Needs an index built by ``IndexBuilder`` (it carries the runner)."""
    if index.runner is None or not rules:
        return []
    hits: list[SignatureHit] = []
    passed: set[str] = set()  # flows a `pass` rule matched: nothing fires on them afterwards
    ordered = sorted(rules, key=lambda r: r.action != "pass")  # pass rules are evaluated first, as in Suricata
    fired: set[tuple[str, str]] = set()
    buffers: dict[tuple[str, bool], bytearray] = {}
    originator: dict[str, tuple[str, int]] = {}
    for row in index.runner.run("payload"):
        src = first(row, "ip.src") or first(row, "ipv6.src")
        dst = first(row, "ip.dst") or first(row, "ipv6.dst")
        proto = "tcp" if first(row, "tcp.srcport") else "udp"
        sp, dp = to_int(first(row, f"{proto}.srcport")), to_int(first(row, f"{proto}.dstport"))
        raw = first(row, "tcp.payload") if proto == "tcp" else first(row, "udp.payload")
        if not src or not dst or sp is None or dp is None or not raw:
            continue
        try:
            data = bytes.fromhex(raw.replace(":", ""))
        except ValueError:
            continue
        key = flow_key(proto, src, sp, dst, dp)
        orig = originator.setdefault(key, (src, sp))
        from_orig = (src, sp) == orig
        frame = to_int(first(row, "frame.number")) or 0
        flags = to_int(first(row, "tcp.flags").replace("0x", ""), 16) if first(row, "tcp.flags") else 0
        if proto == "tcp":
            buf = buffers.setdefault((key, from_orig), bytearray())
            buf.extend(data)
            if len(buf) > BUFFER_CAP:
                del buf[: len(buf) - BUFFER_CAP]
            window = bytes(buf)
        else:
            window = data
        if key in passed:
            continue
        for rule in ordered:
            tag = (rule.sid, key)
            if tag in fired:
                continue
            if rule.to_server is not None and rule.to_server != from_orig:
                continue
            if not _header_ok(rule, proto, src, sp, dst, dp):
                continue
            if rule.flags is not None and not _flags_ok(rule.flags, flags or 0):
                continue
            if not _payload_ok(rule, data, window):
                continue
            if rule.action == "pass":
                passed.add(key)
                break
            fired.add(tag)
            hits.append(SignatureHit(rule.sid, rule.msg, rule.classtype, rule.priority, rule.rev, key, frame,
                                     f"{src}:{sp}", f"{dst}:{dp}", rule.text))
    return hits
