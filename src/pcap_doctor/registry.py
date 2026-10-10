"""Detector discovery.

New detectors are picked up automatically from
``pcap_doctor.detectors`` -- no import list to maintain, and therefore no
merge conflicts when several subagents add detectors in parallel.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

from .detectors.base import Detector

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterator


def all_detectors() -> list[Detector]:
    package = importlib.import_module("pcap_doctor.detectors")
    found: list[Detector] = []
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda m: m.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"pcap_doctor.detectors.{info.name}")
        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, Detector)
                and attr is not Detector
                and getattr(attr, "__module__", "") == module.__name__
            ):
                found.append(attr())
    found.sort(key=lambda d: d.name)
    return found


def enabled_detectors(include: tuple[str, ...] = ()) -> list[Detector]:
    selected = []
    for detector in all_detectors():
        if not detector.enabled:
            continue
        if include and detector.name not in include:
            continue
        selected.append(detector)
    return selected


def iter_detector_table() -> Iterator[tuple[str, str, str, bool]]:  # pragma: no cover
    for detector in all_detectors():
        yield detector.name, detector.title, detector.version, detector.enabled
