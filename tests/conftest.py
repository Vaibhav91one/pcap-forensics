"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
CAPTURES = ROOT / "captures"

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


requires_tshark = pytest.mark.skipif(not tshark_available(), reason="tshark is not installed")


@pytest.fixture(scope="session")
def cache_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Isolate the tshark pass cache so tests never race on a shared cache."""
    path = tmp_path_factory.mktemp("pf-cache")
    import os

    os.environ["PCAP_FORENSICS_CACHE"] = str(path)
    return path


@pytest.fixture(scope="session")
def analyze_capture(cache_dir: Path):
    """Run the full pipeline once per capture and memoise the result."""
    from pcapforensics.pipeline import analyze

    memo: dict[str, object] = {}

    def _run(pcap: Path, **kwargs):
        key = str(pcap)
        if key not in memo:
            out = Path(memo.setdefault("outdirs", []))  # type: ignore[arg-type]
            del out
            memo[key] = analyze(pcap, **kwargs)
        return memo[key]

    out_root = cache_dir.parent / "reports"
    out_root.mkdir(exist_ok=True)

    def run(pcap: Path, **kwargs):
        key = f"{pcap}"
        if key not in memo:
            memo[key] = analyze(pcap, out_root / pcap.name, **kwargs)
        return memo[key]

    return run


def codes(result) -> set[str]:
    return {f.code for f in result.report.findings}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def fixture(name: str) -> Path:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"fixture {name} missing; run: python scripts/make_fixtures.py")
    return path
