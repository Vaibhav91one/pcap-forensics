"""Policy: validate filter options and drop findings after detection (the only filter step)."""

from __future__ import annotations

from collections.abc import Iterable

from .models import SEVERITY_ORDER, Finding
from .registry import all_detectors
from .rules import CATEGORIES, category_of

SEVERITIES = tuple(SEVERITY_ORDER)


class PolicyError(ValueError):
    """An option value that is not one of the valid choices."""


def _check(option: str, values: Iterable[str], valid: Iterable[str]) -> None:
    allowed = list(valid)
    unknown = [v for v in values if v not in allowed]
    if unknown:
        raise PolicyError(f"{option}: unknown value(s) {', '.join(unknown)}; valid: {', '.join(allowed)}")


def validate(
    *,
    only: Iterable[str] = (),
    categories: Iterable[str] = (),
    min_severity: str | None = None,
    fail_on: str | None = None,
) -> None:
    """Raise PolicyError for any unknown value, before tshark runs."""
    _check("--only", only, (d.name for d in all_detectors()))
    _check("--category", categories, CATEGORIES)
    _check("--min-severity", [min_severity] if min_severity else [], SEVERITIES)
    _check("--fail-on", [fail_on] if fail_on else [], ("none", *SEVERITIES))


def apply(
    findings: list[Finding], *, categories: Iterable[str] = (), min_severity: str | None = None
) -> list[Finding]:
    """Keep findings in `categories` (all when empty) at or above `min_severity`."""
    wanted = set(categories)
    threshold = SEVERITY_ORDER[min_severity] if min_severity else 99
    return [
        f
        for f in findings
        if (not wanted or category_of(f.code) in wanted) and SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]
