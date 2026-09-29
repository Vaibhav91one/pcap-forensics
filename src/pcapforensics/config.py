"""Project config: ``pcap-doctor.toml`` or ``[tool.pcap-doctor]`` in ``pyproject.toml`` (issue #57).

    disable = ["DNS_CLEARTEXT"]              # codes never reported
    [severity]
    TLS_CERT_EXPIRING = "low"                # re-rate a code; the finding id is kept
    [[allow]]                                # accept one known finding, with a reason
    code = "TLS_CIPHER_WEAK"                 # code / subject / flow_key: fnmatch patterns, all must match
    subject = "10.0.0.20*"
    reason = "legacy appliance, replacement tracked in OPS-12"
    profile = "ota"                          # start from a preset (see PROFILES); keys above override it
    categories = ["Crypto", "DNS"]           # same meaning as --category
    fail_on = "high"                         # same meaning as --fail-on

Command-line flags win over the config, and the config wins over its profile.
Every suppression is written to the report notes, so nothing disappears silently.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .models import SEVERITY_ORDER, Finding
from .policy import SEVERITIES, PolicyError
from .rules import CATEGORIES, RULES

CONFIG_NAME = "pcap-doctor.toml"
_KEYS = ("profile", "categories", "fail_on", "disable", "severity", "allow")

#: Presets are config fragments. "ota": firmware/OTA-update traffic, where what matters is whether the image and
#: its credentials travel protected and are resolved safely; VoIP and network-shape findings are noise there.
PROFILES: dict[str, dict[str, Any]] = {
    "ota": {"categories": ["Crypto", "Credentials", "Cleartext", "DNS"], "fail_on": "high"},
}
_ALLOW_MATCH = ("code", "subject", "flow_key")


class ConfigError(PolicyError):
    """A config file that cannot be read or holds an unknown key, code or value."""


@dataclass(frozen=True)
class Allow:
    reason: str
    code: str | None = None
    subject: str | None = None
    flow_key: str | None = None

    def matches(self, f: Finding) -> bool:
        return (
            (self.code is None or fnmatchcase(f.code, self.code))
            and (self.subject is None or any(fnmatchcase(s, self.subject) for s in f.subjects))
            and (self.flow_key is None or (f.flow_key is not None and fnmatchcase(f.flow_key, self.flow_key)))
        )


@dataclass(frozen=True)
class Config:
    source: str | None = None
    profile: str | None = None
    categories: tuple[str, ...] = ()
    fail_on: str | None = None
    disable: frozenset[str] = frozenset()
    severity: dict[str, str] = field(default_factory=dict)
    allow: tuple[Allow, ...] = ()


def _codes(where: str, codes: list[Any]) -> None:
    unknown = [str(c) for c in codes if c not in RULES]
    if unknown:
        raise ConfigError(f"{where}: unknown code(s) {', '.join(unknown)}; see `pcap-doctor rules list`")


def parse(data: dict[str, Any], source: str, profile: str | None = None) -> Config:
    """Validate a `[tool.pcap-doctor]`-shaped table; raise ConfigError naming the bad key or value.

    `profile` (from `--profile`) replaces the table's own `profile` key; the preset fills keys the table leaves out.
    """
    unknown = sorted(set(data) - set(_KEYS))
    if unknown:
        raise ConfigError(f"{source}: unknown key(s) {', '.join(unknown)}; valid: {', '.join(_KEYS)}")
    name = profile or data.get("profile")
    if name is not None:
        if name not in PROFILES:
            raise ConfigError(f"{'--profile' if profile else source}: unknown profile {name}; valid: {', '.join(PROFILES)}")
        data = {**PROFILES[name], **data}
    categories = data.get("categories", [])
    if not isinstance(categories, list):
        raise ConfigError(f"{source}: categories must be a list")
    bad_categories = [str(c) for c in categories if c not in CATEGORIES]
    if bad_categories:
        raise ConfigError(f"{source}: unknown categories {', '.join(bad_categories)}; valid: {', '.join(CATEGORIES)}")
    fail_on = data.get("fail_on")
    if fail_on is not None and fail_on not in ("none", *SEVERITIES):
        raise ConfigError(f"{source}: fail_on {fail_on} invalid; valid: none, {', '.join(SEVERITIES)}")
    disable = data.get("disable", [])
    if not isinstance(disable, list):
        raise ConfigError(f"{source}: disable must be a list of codes")
    _codes(f"{source}: disable", disable)
    severity = data.get("severity", {})
    if not isinstance(severity, dict):
        raise ConfigError(f"{source}: [severity] must be a table of CODE = \"severity\"")
    _codes(f"{source}: [severity]", list(severity))
    bad = [f"{code}={value}" for code, value in severity.items() if value not in SEVERITY_ORDER]
    if bad:
        raise ConfigError(f"{source}: [severity] invalid value(s) {', '.join(bad)}; valid: {', '.join(SEVERITY_ORDER)}")
    allow = []
    for i, entry in enumerate(data.get("allow", [])):
        where = f"{source}: [[allow]] #{i + 1}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")
        extra = sorted(set(entry) - {"reason", *_ALLOW_MATCH})
        if extra:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(extra)}; valid: reason, {', '.join(_ALLOW_MATCH)}")
        if not str(entry.get("reason", "")).strip():
            raise ConfigError(f"{where}: reason is required")
        if not any(k in entry for k in _ALLOW_MATCH):
            raise ConfigError(f"{where}: needs at least one of {', '.join(_ALLOW_MATCH)}")
        allow.append(Allow(**{k: str(v) for k, v in entry.items()}))
    return Config(
        source=source,
        profile=name,
        categories=tuple(categories),
        fail_on=fail_on,
        disable=frozenset(disable),
        severity=dict(severity),
        allow=tuple(allow),
    )


def load(path: Path | None = None, cwd: Path | None = None, profile: str | None = None) -> Config:
    """Explicit `path`, else `pcap-doctor.toml`, else `[tool.pcap-doctor]` in pyproject.toml, in `cwd`."""
    if path is None:
        here = cwd or Path.cwd()
        for candidate in (here / CONFIG_NAME, here / "pyproject.toml"):
            if candidate.is_file():
                table = _read(candidate)
                if table is not None:
                    return parse(table, str(candidate), profile)
        return parse({}, f"profile {profile}", profile) if profile else Config()
    table = _read(path)
    if table is None:
        raise ConfigError(f"{path}: no [tool.pcap-doctor] table")
    return parse(table, str(path), profile)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    if path.name == "pyproject.toml":
        table = data.get("tool", {}).get("pcap-doctor")
        return table if isinstance(table, dict) else None
    return data


def apply(findings: list[Finding], config: Config) -> tuple[list[Finding], list[str]]:
    """Re-rate, disable and allow findings; return the kept findings and one note per suppression kind."""
    notes: list[str] = []
    rerated = 0
    kept: list[Finding] = []
    disabled: dict[str, int] = {}
    allowed: dict[str, int] = {}
    for f in findings:
        if f.code in config.severity and config.severity[f.code] != f.severity:
            f = f.model_copy(update={"severity": config.severity[f.code]})
            rerated += 1
        if f.code in config.disable:
            disabled[f.code] = disabled.get(f.code, 0) + 1
            continue
        rule = next((a for a in config.allow if a.matches(f)), None)
        if rule is not None:
            allowed[rule.reason] = allowed.get(rule.reason, 0) + 1
            continue
        kept.append(f)
    if rerated:
        notes.append(f"[config] re-rated {rerated} finding(s) by [severity] in {config.source}")
    if disabled:
        codes = ", ".join(f"{code} x{n}" for code, n in sorted(disabled.items()))
        notes.append(f"[config] disabled {sum(disabled.values())} finding(s) in {config.source}: {codes}")
    for reason, n in allowed.items():
        notes.append(f"[config] allowed {n} finding(s) in {config.source}: {reason}")
    return kept, notes
