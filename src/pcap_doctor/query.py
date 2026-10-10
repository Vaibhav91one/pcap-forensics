"""A small query language over the rows pcap-doctor already builds: flows, hosts, log rows, findings (issue #198).

Wireshark's display filter is for frames and stays tshark's job (``packets -Y``). This is the same idea for the
analysed data, in the spirit of zeek-cut / Brim filters::

    app_proto == "tls" and bytes > 10000
    dst_port in {80 8080} and not encrypted
    server_name contains "example" or host matches "^cdn[0-9]+\\."
    endpoint_a == 10.0.0.0/8

Fields come from the rows themselves (nested keys use dots), comparing a list field matches when any element
does, ``a == b`` with a CIDR on the right is a membership test, and an unknown field is an error that lists the
known ones. The parser is a plain recursive descent: nothing is ever passed to ``eval``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

Row = dict[str, Any]


class QueryError(ValueError):
    pass


_TOKEN = re.compile(
    r"""\s*(?:
      (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
     |(?P<op>==|!=|<=|>=|&&|\|\||<|>|~|!|\(|\)|\{|\}|\[|\]|,)
     |(?P<word>[^\s"'()<>=!~{}\[\],&|]+)
    )""",
    re.X,
)
_NUMBER = re.compile(r"-?\d+(\.\d+)?$")
_ALIASES = {"&&": "and", "||": "or", "!": "not", "~": "matches"}
_KEYWORDS = {"and", "or", "not", "in", "contains", "matches"}


@dataclass
class _Tok:
    kind: str  # str | op | word
    text: str


def _tokenize(text: str) -> list[_Tok]:
    out: list[_Tok] = []
    pos = 0
    while pos < len(text):
        if not text[pos:].strip():
            break
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise QueryError(f"cannot read the query at {text[pos:pos + 12]!r}")
        pos = m.end()
        kind = m.lastgroup or "word"
        raw = m.group(kind)
        if kind == "str":
            raw = re.sub(r"\\(.)", r"\1", raw[1:-1])
        elif kind == "word" and raw.lower() in _KEYWORDS:
            kind, raw = "op", raw.lower()
        elif kind == "op":
            raw = _ALIASES.get(raw, raw)
        out.append(_Tok(kind, raw))
    return out


def _flatten(row: Row, prefix: str = "") -> Row:
    flat: Row = {}
    for key, value in row.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, name + "."))
        else:
            flat[name] = value
    return flat


# AST: ("or"|"and", a, b) | ("not", a) | ("cmp", field, op, value) | ("field", name)
class _Parser:
    def __init__(self, text: str, fields: set[str] | None) -> None:
        self.toks = _tokenize(text)
        self.i = 0
        self.fields = fields

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> _Tok:
        tok = self.peek()
        if tok is None:
            raise QueryError("the query ends too early")
        self.i += 1
        return tok

    def accept(self, kind: str, text: str) -> bool:
        tok = self.peek()
        if tok and tok.kind == kind and tok.text == text:
            self.i += 1
            return True
        return False

    def parse(self) -> Any:
        if not self.toks:
            raise QueryError("empty query")
        node = self.or_()
        if self.peek() is not None:
            raise QueryError(f"unexpected {self.peek().text!r}")  # type: ignore[union-attr]
        return node

    def or_(self) -> Any:
        node = self.and_()
        while self.accept("op", "or"):
            node = ("or", node, self.and_())
        return node

    def and_(self) -> Any:
        node = self.not_()
        while self.accept("op", "and"):
            node = ("and", node, self.not_())
        return node

    def not_(self) -> Any:
        if self.accept("op", "not"):
            return ("not", self.not_())
        return self.cmp()

    def field(self, name: str) -> str:
        if self.fields is not None and name not in self.fields:
            raise QueryError(f"unknown field {name!r}; fields: {', '.join(sorted(self.fields))}")
        return name

    def cmp(self) -> Any:
        if self.accept("op", "("):
            inner = self.or_()
            if not self.accept("op", ")"):
                raise QueryError("missing )")
            return inner
        left = self.take()
        if left.kind != "word":
            raise QueryError(f"expected a field name, got {left.text!r}")
        name = self.field(left.text)
        tok = self.peek()
        negate = False
        if tok and tok.kind == "op" and tok.text == "not" and self.i + 1 < len(self.toks) and self.toks[self.i + 1].text == "in":
            self.i += 1
            negate = True
            tok = self.peek()
        if not tok or tok.kind != "op" or tok.text not in {"==", "!=", "<", "<=", ">", ">=", "contains", "matches", "in"}:
            return ("field", name)
        op = self.take().text
        if op == "in":
            node: Any = ("cmp", name, "in", self.set_())
        else:
            node = ("cmp", name, op, self.value())
            if op == "matches":
                try:
                    re.compile(node[3][1])
                except re.error as exc:
                    raise QueryError(f"bad regular expression: {exc}") from exc
        return ("not", node) if negate else node

    def value(self) -> tuple[str, Any]:
        tok = self.take()
        if tok.kind == "str":
            return ("lit", tok.text)
        if tok.kind != "word":
            raise QueryError(f"expected a value, got {tok.text!r}")
        if self.fields is not None and tok.text in self.fields:
            return ("field", tok.text)
        if _NUMBER.match(tok.text):
            return ("lit", float(tok.text) if "." in tok.text else int(tok.text))
        if tok.text.lower() in ("true", "false"):
            return ("lit", tok.text.lower() == "true")
        return ("lit", tok.text)

    def set_(self) -> list[tuple[str, Any]]:
        if not (self.accept("op", "{") or self.accept("op", "[")):
            raise QueryError("`in` needs a set: in {a b c}")
        items = []
        while not (self.accept("op", "}") or self.accept("op", "]")):
            self.accept("op", ",")
            items.append(self.value())
        return items


def _values(v: Any) -> list[Any]:
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _eq(a: Any, b: Any) -> bool:
    if isinstance(b, str) and "/" in b and a is not None:
        try:
            return ipaddress.ip_address(str(a)) in ipaddress.ip_network(b, strict=False)
        except ValueError:
            pass
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b or str(a).lower() == str(b).lower()
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return str(a).lower() == str(b).lower() if a is not None else False


def _order(a: Any, b: Any, op: str) -> bool:
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        pair: tuple[Any, Any] = (a, b)
    else:
        pair = (str(a), str(b))
    return bool({"<": pair[0] < pair[1], "<=": pair[0] <= pair[1], ">": pair[0] > pair[1], ">=": pair[0] >= pair[1]}[op])


def _truthy(v: Any) -> bool:
    return bool(v) and v != "0" if not isinstance(v, (int, float)) else v != 0


def _run(node: Any, row: Row) -> bool:
    kind = node[0]
    if kind == "or":
        return _run(node[1], row) or _run(node[2], row)
    if kind == "and":
        return _run(node[1], row) and _run(node[2], row)
    if kind == "not":
        return not _run(node[1], row)
    if kind == "field":
        return any(_truthy(x) for x in _values(row.get(node[1])))
    _, name, op, rhs = node
    have = _values(row.get(name))

    def literal(item: tuple[str, Any]) -> Any:
        return row.get(item[1]) if item[0] == "field" else item[1]

    if op == "in":
        wanted = [literal(i) for i in rhs]
        return any(_eq(h, w) for h in have for w in wanted)
    want = literal(rhs)
    if op == "==":
        return any(_eq(h, want) for h in have)
    if op == "!=":
        return not any(_eq(h, want) for h in have)
    if op in ("<", "<=", ">", ">="):
        return any(h is not None and _order(h, want, op) for h in have)
    if op == "contains":
        return any(str(want).lower() in str(h).lower() for h in have if h is not None)
    return any(re.search(str(want), str(h)) is not None for h in have if h is not None)  # matches


class Query:
    """A compiled query. ``Query(text, fields)`` checks every field name once, before any row is read."""

    def __init__(self, text: str, fields: Iterable[str] | None = None) -> None:
        self.text = text
        self.ast = _Parser(text, set(fields) if fields is not None else None).parse()

    def matches(self, row: Row) -> bool:
        return _run(self.ast, _flatten(row))


def filter_rows(rows: list[Row], text: str) -> list[Row]:
    """Rows matching ``text``; the schema is the union of the rows' keys (an empty source matches nothing)."""
    if not rows:
        Query(text, None)  # still report a syntax error
        return []
    fields: set[str] = set()
    for row in rows:
        fields |= set(_flatten(row))
    query = Query(text, fields)
    return [r for r in rows if query.matches(r)]


# -- sources -----------------------------------------------------------------
def _dump(items: Iterable[Any]) -> list[Row]:
    return [i.model_dump(mode="json") for i in items]


def _flow_rows(index: Any) -> list[Row]:
    rows = _dump(index.flows.values())
    for r in rows:
        r["dst_port"], r["src_port"] = r["port_b"], r["port_a"]
    return rows


def _finding_rows(index: Any) -> list[Row]:
    from .registry import enabled_detectors

    found = []
    for detector in enabled_detectors():
        try:
            found += detector.detect(index)
        except Exception:  # one bad detector must not sink the query, as in the pipeline
            continue
    return _dump(found)


#: source name -> function(CaptureIndex) -> rows. Other modules add their own (log tables, #199).
SOURCES: dict[str, Callable[[Any], list[Row]]] = {
    "flows": _flow_rows,
    "hosts": lambda ix: _dump(ix.hosts.values()),
    "tls": lambda ix: _dump(ix.tls.values()),
    "http": lambda ix: _dump(ix.http),
    "dns": lambda ix: _dump(ix.dns),
    "sip": lambda ix: _dump(ix.sip),
    "rtp": lambda ix: _dump(ix.rtp),
    "ssh": lambda ix: _dump(ix.ssh),
    "quic": lambda ix: _dump(ix.quic),
    "services": lambda ix: _dump(ix.services),
    "smb": lambda ix: _dump(ix.smb),
    "findings": _finding_rows,
}


def rows_of(index: Any, source: str) -> list[Row]:
    if source not in SOURCES:
        raise QueryError(f"unknown source {source!r}; sources: {', '.join(sorted(SOURCES))}")
    return SOURCES[source](index)
