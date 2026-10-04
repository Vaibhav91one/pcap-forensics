"""What does widening a tshark pass filter cost? A stopwatch, not a fixture.

    python scripts/corpus_bench.py --packets 60000
    python scripts/corpus_bench.py --rebuild

Built to settle a real argument. Widening the TLS pass display filter is on the hot path for every
capture the tool ever analyses, and the project quotes 41 s for a 120 MB / 509k-packet capture. Before
changing that filter the cost has to be measured, and the corpus cannot measure it: 60 of its 219
captures contain six TLS rows between them, because they are small dissector test files rather than
real traffic.

So this replays the packets of a real TLS capture many times to make a capture big enough to time.

WHAT THIS IS NOT. Sequence numbers are not corrected, so tshark does not reassemble the replayed
sessions. That is deliberate: the question is what a wider display filter adds, and that work is
per-packet dissection and filter matching, which a replay exercises identically. Treat the number as
a filter cost, not a reassembly cost, and say so when quoting it.

Nothing here is written into tests/fixtures. It is a measurement tool and its output goes to /tmp.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH_PCAP = Path("/tmp/bench-tls-large.pcap")

SOURCE = ROOT / "corpus" / "blobs" / "capture" / "ws-tls12-dsb.pcapng" / "tls12-dsb.pcapng"

#: The filter as it stands, and the two forms a take-on might widen it to. The middle one is the
#: worst case: every application record matches, which is what a legacy session looks like.
FILTERS: dict[str, str] = {
    "today: handshake || alert": "tls.handshake || tls.alert_message",
    "wider: + all application data": (
        "tls.handshake || tls.alert_message || tls.record.content_type == 23"
    ),
    "wider: + only legacy application data": (
        "tls.handshake || tls.alert_message "
        "|| (tls.record.content_type == 23 && tls.record.version != 0x0303)"
    ),
}

PEAK_MEMORY = re.compile(r"^\s*(\d+)\s+maximum resident set size", re.MULTILINE)


def build(packets: int) -> Path:
    """Replay a real TLS capture until it has ``packets`` frames."""
    from scapy.all import TCP, PcapReader, PcapWriter

    if not SOURCE.exists():
        print(
            f"missing {SOURCE}. Run: python scripts/corpus_fetch.py --kind capture",
            file=sys.stderr,
        )
        raise SystemExit(2)

    original = list(PcapReader(str(SOURCE)))
    if not original:
        print(f"{SOURCE} holds no packets", file=sys.stderr)
        raise SystemExit(2)

    BENCH_PCAP.parent.mkdir(parents=True, exist_ok=True)
    base = float(original[0].time)
    written = 0
    started = time.monotonic()
    with PcapWriter(str(BENCH_PCAP), append=False, sync=True) as writer:
        while written < packets:
            for offset, packet in enumerate(original):
                if written >= packets:
                    break
                clone = packet.__class__(bytes(packet))
                clone.time = base + (written + offset) * 0.0001
                if clone.haslayer(TCP):
                    # Each replay is a distinct conversation, so nothing is merged away silently.
                    clone[TCP].sport = 40000 + (written % 20000)
                    clone[TCP].dport = 443
                writer.write(clone)
                written += 1
    size = BENCH_PCAP.stat().st_size
    print(
        f"replayed {len(original)} real TLS packets {written} times "
        f"-> {BENCH_PCAP} ({size / 1048576:.1f} MB) in {time.monotonic() - started:.1f}s\n"
    )
    return BENCH_PCAP


def time_filter(display_filter: str, repeats: int) -> tuple[int, float, float]:
    """(rows, best seconds, peak MB) for one display filter."""
    best = None
    rows = 0
    peak = 0.0
    for _ in range(repeats):
        started = time.monotonic()
        done = subprocess.run(
            ["/usr/bin/time", "-l", "tshark", "-r", str(BENCH_PCAP),
             "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True,
        )
        elapsed = time.monotonic() - started
        rows = len([line for line in done.stdout.splitlines() if line.strip()])
        found = PEAK_MEMORY.search(done.stderr)
        if found:
            peak = int(found.group(1)) / 1048576
        best = elapsed if best is None else min(best, elapsed)
    return rows, best or 0.0, peak


def tls_records() -> int:
    done = subprocess.run(
        ["tshark", "-r", str(BENCH_PCAP), "-Y", "tls", "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True,
    )
    return len([line for line in done.stdout.splitlines() if line.strip()])


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure what a tshark pass filter costs.")
    parser.add_argument("--packets", type=int, default=60000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--filter", action="append", default=None, help="measure this filter instead")
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()

    if args.rebuild or not BENCH_PCAP.exists():
        build(args.packets)
    if not BENCH_PCAP.exists():
        print("no benchmark capture", file=sys.stderr)
        return 2

    records = tls_records()
    print(
        f"{BENCH_PCAP.name}: {BENCH_PCAP.stat().st_size / 1048576:.1f} MB, "
        f"{records} TLS records dissected"
    )
    if records < 100:
        print("WARNING: tshark is barely dissecting this capture; the numbers below mean little.",
              file=sys.stderr)

    filters = dict(FILTERS)
    if args.filter:
        filters = {f"custom {index}": text for index, text in enumerate(args.filter)}

    print()
    print(f"{'filter':44} {'rows':>9} {'seconds':>9} {'peak MB':>9}")
    baseline = None
    for name, display_filter in filters.items():
        rows, seconds, peak = time_filter(display_filter, args.repeats)
        if baseline is None:
            baseline = (rows, seconds, peak)
        ratio = f"{seconds / baseline[1]:.2f}x" if baseline[1] else "-"
        print(f"{name:44} {rows:>9} {seconds:>9.2f} {peak:>9.0f}   ({ratio})")

    print()
    print("Reminder: this is a filter cost, not a reassembly cost. Sequence numbers are not")
    print("corrected on replay, so tshark does not reassemble the repeated sessions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
