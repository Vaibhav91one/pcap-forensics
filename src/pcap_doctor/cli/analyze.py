"""``analyze``: run the detectors on a capture and write the report."""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import nullcontext
from pathlib import Path

import typer
from rich.markup import escape

from ..baseline import load_baseline, new_since, version_drift
from ..clipboard import copy as copy_text
from ..config import load as load_config
from ..handoff import _subprocess_run, detect_agents, in_agent, offer, safe_mode
from ..keymaterial import collect, firmware_key_spkis
from ..models import SEVERITY_ORDER
from ..output import json_envelope, sarif
from ..pipeline import analyze
from ..policy import PolicyError, validate
from ..scoring import score
from ._browse import ICON, browse, supported
from ._console import console, tshark_errors
from ._summary import render


def analyze_cmd(
    pcap: Path = typer.Argument(..., exists=True, readable=True, help="pcap or pcapng file"),
    out: Path = typer.Option(None, "--out", "-o", help="output directory (default: <capture>.pf-report)"),
    only: list[str] = typer.Option(None, "--only", help="run only these detector ids (repeatable)"),
    category: list[str] = typer.Option(
        None, "--category", help="keep only findings in these categories (repeatable; see `rules`)"
    ),
    min_severity: str = typer.Option(
        None, "--min-severity", help="drop findings below this severity (critical|high|medium|low|info)"
    ),
    fail_on: str = typer.Option(
        None,
        "--fail-on",
        help="exit non-zero when a finding at or above this severity exists (none|critical|high|medium|low|info;"
        " default: the config's, else none)",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="ignore the tshark pass cache"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="suppress the console summary"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="list every finding, not the top 3 per category"),
    show_score: bool = typer.Option(False, "--score", help="print only the 0-100 health score"),
    as_json: bool = typer.Option(False, "--json", help="print only the doctor/1 JSON envelope (docs/doctor-contract.md)"),
    json_out: Path = typer.Option(None, "--json-out", help="also write the JSON envelope to this file"),
    baseline_path: Path = typer.Option(
        None, "--baseline", exists=True, dir_okay=False, help="earlier --json envelope (or report.json): report and gate only new findings; a new one exits 3"
    ),
    sarif_out: Path = typer.Option(None, "--sarif", help="also write the shown findings as SARIF 2.1.0 to this file"),
    config_path: Path = typer.Option(
        None, "--config", exists=True, dir_okay=False, help="config file (default: ./pcap-doctor.toml or [tool.pcap-doctor] in ./pyproject.toml)"
    ),
    profile: str = typer.Option(None, "--profile", help="start from a preset (ota); config and flags override it"),
    tls_key: list[Path] = typer.Option(
        None, "--tls-key", exists=True, dir_okay=False,
        help="TLS private key (PEM) to decrypt RSA-key-exchange sessions in your own capture (repeatable)",
    ),
    tls_key_password: str = typer.Option("", "--tls-key-password", help="passphrase for --tls-key, if encrypted"),
    keys_from: Path = typer.Option(
        None, "--keys-from", exists=True, file_okay=False,
        help="load every PEM private key under this extracted-firmware tree",
    ),
    firmware: list[Path] = typer.Option(
        None, "--firmware", exists=True, file_okay=False,
        help="extracted-firmware tree to correlate against: a session whose server key ships here is flagged "
        "TLS_KEY_IN_FIRMWARE (repeatable)",
    ),
    keylog: Path = typer.Option(
        None, "--keylog", exists=True, dir_okay=False, envvar="PCAP_DOCTOR_KEYLOG",
        help="TLS key-log file (SSLKEYLOGFILE format) to decrypt forward-secret sessions",
    ),
    psk: str = typer.Option("", "--psk", envvar="PCAP_DOCTOR_PSK", help="TLS/DTLS pre-shared key, hex"),
    no_handoff: bool = typer.Option(False, "--no-handoff", help="never offer to hand a finding to an AI agent"),
    safe: bool = typer.Option(
        False, "--safe", help="launch AI agents with their approval prompts (also PCAP_DOCTOR_HANDOFF_SAFE=1)"
    ),
) -> None:
    """Analyze a capture, write the report files and print a scored summary."""
    try:
        validate(only=only or (), categories=category or (), min_severity=min_severity, fail_on=fail_on)
        config = load_config(config_path, profile=profile)
        keys = collect(tls_key, tls_key_password=tls_key_password, keys_from=keys_from, keylog=keylog, psk=psk)
        firmware_keys = (
            firmware_key_spkis(firmware or [], extra_keys=keys.tls_keys)
            if (firmware or keys.tls_keys)
            else {}
        )
    except PolicyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    # Flags win over the config, which wins over its profile.
    category = category or list(config.categories)
    fail_on = fail_on or config.fail_on or "none"
    try:
        baseline = load_baseline(baseline_path) if baseline_path is not None else None
    except (OSError, ValueError) as exc:
        console.print(f"[red]--baseline {baseline_path}: not a pcap-doctor report ({type(exc).__name__})[/red]")
        raise typer.Exit(code=2) from exc
    # The interactive screens run only for a person at a terminal; pipes, files, CI, agents and the machine
    # outputs (--json, --score, -q) keep their exact output.
    interactive = (
        not (quiet or show_score or as_json or no_handoff)
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and not os.environ.get("CI")
        and not in_agent()
        and supported()
    )
    started = time.monotonic()
    try:
        with tshark_errors(), (console.status("Scanning…") if interactive else nullcontext()) as status:
            result = analyze(
                pcap,
                out,
                only=tuple(only or ()),
                min_severity=min_severity,
                categories=tuple(category or ()),
                use_cache=not no_cache,
                config=config,
                keys=keys,
                firmware_keys=firmware_keys,
                progress=(lambda stage: status.update(f"{stage}…")) if status is not None else None,
            )
    except KeyboardInterrupt:
        raise typer.Exit(code=130) from None

    # The artifacts on disk stay complete; with a baseline everything shown or gated is the new findings only.
    shown = result.report
    if baseline is not None:
        shown = shown.model_copy(update={"findings": new_since(baseline, shown.findings)})
        for name in version_drift(baseline, result.report):
            typer.echo(f"warning: detector {name} changed version since the baseline; its findings may all be new", err=True)
    threshold = None if fail_on == "none" else SEVERITY_ORDER.get(fail_on)
    tripped = (
        []
        if threshold is None
        else [f for f in shown.findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]
    )
    exit_code = (3 if baseline is not None else 1) if tripped else 0  # 3: a new finding at the threshold (doctor/1)
    envelope = json_envelope(result.report, exit_code, baseline) if (as_json or json_out) else None
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)  # like --out: never a traceback for a new folder
        json_out.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    if sarif_out is not None:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(
            json.dumps(sarif(shown, artifact_uri=pcap.as_posix(), score_of=result.report.findings), indent=2) + "\n",
            encoding="utf-8",
        )
    if as_json:
        typer.echo(json.dumps(envelope, indent=2))
    elif show_score:
        typer.echo(score(shown.findings)[0])
    elif interactive:
        seconds = time.monotonic() - started
        console.print(f"[green]✔[/green] Scanned {result.report.stats.packets:,} packets in {seconds:.1f}s")
        if baseline is not None:
            console.print(f"{len(shown.findings)} new finding(s) since the baseline ({len(result.report.findings)} in total)")
        ranked = sorted(shown.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        for finding in ranked[:20]:
            icon, style = ICON[finding.severity]
            console.print(f"  [{style}]{icon}[/{style}] {finding.code}  {escape(finding.title)}", highlight=False)
        if len(ranked) > 20:
            console.print(f"  [dim]… {len(ranked) - 20} more in Review[/dim]")
        browse(
            console,
            shown,
            safe=safe_mode(safe),
            agents=detect_agents(),
            copy=copy_text,
            run=_subprocess_run,
        )
        console.print(f"Report: {escape(str(result.outdir))}/index.md · 03-findings.md · report.json")
    elif not quiet:
        if baseline is not None:
            console.print(f"{len(shown.findings)} new finding(s) since the baseline ({len(result.report.findings)} in total)")
        render(console, shown, verbose=verbose)
        console.print()
        for artifact in result.artifacts:
            console.print(f"  wrote {artifact}")
    if tripped and not (quiet or show_score or as_json):
        console.print(f"[red]{len(tripped)} finding(s) at or above {fail_on}; failing as requested[/red]")
    if not (interactive or quiet or show_score or as_json or no_handoff):
        offer(console, shown, safe=safe)  # agent guidance inside an agent; the plain menu where raw keys are missing
    raise typer.Exit(code=exit_code)


def register(app: typer.Typer) -> None:
    app.command("analyze")(analyze_cmd)
