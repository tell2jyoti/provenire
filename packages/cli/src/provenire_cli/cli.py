"""The `provenire` CLI (cli-spec §2, feature F6, layer: cli).

Wires the engine's F1→F5 pipeline behind ``provenire scan <target>`` and exits
with a CI-meaningful code (FR-13). The CLI is the sanctioned path for stdio /
private servers (FR-05): it scans locally and never transmits the manifest.

Testable seam (cli-spec §1): the live MCP transport adapter is a later
integration slice, so the connection is an **injected** ``connect`` factory —
unit tests supply an in-memory fake ``Session``; ``_default_connect`` is a stub
until the transport slice lands (C6). Everything from a connected session onward
is implemented and unit-tested here.

Imports only ``provenire_engine`` (open core) — never ``control_plane``
(architecture law) — and names no regulation.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

from provenire_engine import (
    Report,
    ScanResult,
    TargetUnreachable,
    build_report,
    detect_over_privilege,
    detect_poisoning,
    scan,
    score_findings,
)
from provenire_engine.connect.session import Session, Transport
from provenire_engine.finding import Severity

Connect = Callable[[str, Transport, float], Awaitable[Session]]

_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")

# Exit codes — the FR-13 CI contract (cli-spec C3).
EXIT_PASS = 0
EXIT_GATE_FAIL = 1
EXIT_USAGE = 2  # emitted by argparse itself
EXIT_UNREACHABLE = 3
EXIT_ERROR = 4  # any other scan/output failure — never conflated with a gate breach


async def _default_connect(target: str, transport: Transport, timeout: float) -> Session:
    """C6 stub: the real stdio/streamable_http adapter lands with the transport slice."""
    # The target may be a stdio command carrying secrets — keep it out of the
    # message (no connection is even attempted here).
    raise TargetUnreachable(
        "live MCP transport adapter is not yet wired (lands with the transport slice)"
    )


def run_scan(
    target: str,
    *,
    fail_on: str = "high",
    timeout: float = 10.0,
    transport: Transport = "stdio",
    json_out: bool = False,
    output_dir: str | None = None,
    connect: Connect = _default_connect,
) -> int:
    """Run one scan and return the process exit code (cli-spec C0–C6).

    Sync boundary over the async engine (``asyncio.run``); prints to stdout/stderr
    and writes files only when ``output_dir`` is given. Never calls ``sys.exit``.
    """
    try:
        report, result = asyncio.run(_scan(target, fail_on, timeout, transport, connect))
    except TargetUnreachable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except Exception as exc:  # noqa: BLE001 — a crash must not masquerade as a gate breach
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        _emit(report, result, json_out=json_out, output_dir=output_dir)
    except OSError as exc:
        print(f"error: failed to write artifacts: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_GATE_FAIL if result.score.gate == "fail" else EXIT_PASS


async def _scan(
    target: str, fail_on: str, timeout: float, transport: Transport, connect: Connect
) -> tuple[Report, ScanResult]:
    session = await connect(target, transport, timeout)
    manifest = await scan(session, transport=transport, timeout=timeout)
    findings = detect_poisoning(manifest) + detect_over_privilege(manifest)
    result = score_findings(findings, gate_threshold=fail_on)  # type: ignore[arg-type]
    return build_report(manifest, result), result


# --- output (cli-spec C4) --------------------------------------------------
def _emit(report: Report, result: ScanResult, *, json_out: bool, output_dir: str | None) -> None:
    if json_out:
        print(report.json)  # already-serialized artifact; JSON-escapes control bytes
    else:
        print(_summary(result))
    if output_dir is not None:
        paths = _write_artifacts(report, output_dir)
        # Keep stdout pure JSON in --json mode: paths go to stderr there.
        stream = sys.stderr if json_out else sys.stdout
        for p in paths:
            print(f"wrote {p}", file=stream)


def _safe(text: str) -> str:
    """Strip terminal control bytes from attacker-controlled text (C4 / security).

    Finding text comes from a hostile MCP server; printed raw to a TTY, an ESC
    sequence could clear the screen or hide findings. Drop C0/C1 controls (incl.
    ESC, and our own field separators) so the value renders as inert text.
    """
    return "".join(c for c in text if ord(c) >= 0x20 and not 0x7F <= ord(c) <= 0x9F)


def _summary(result: ScanResult) -> str:
    score = result.score
    lines = [
        f"gate: {score.gate}",
        "counts: " + " ".join(f"{sev}={score.counts[sev]}" for sev in _SEVERITIES),
        f"worst: {score.worst if score.worst else 'none'}",
    ]
    if result.findings:
        lines.append("")
        for f in result.findings:
            lines.append(
                f"{f.severity}\t{f.finding_type}\t{_safe(f.entity_ref)}\t— {_safe(f.rationale)}"
            )
    else:
        lines.append("no findings")
    return "\n".join(lines)


def _write_artifacts(report: Report, output_dir: str) -> list[Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "report.json"
    html_path = directory / "report.html"
    json_path.write_text(report.json, encoding="utf-8")
    html_path.write_text(report.html, encoding="utf-8")
    return [json_path, html_path]


# --- argument parsing (cli-spec C1) ----------------------------------------
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provenire", description="Scan a live MCP server.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_p = sub.add_parser("scan", help="Scan an MCP server and report findings.")
    scan_p.add_argument("target", help="MCP server target (URL or stdio command).")
    scan_p.add_argument(
        "--fail-on",
        choices=_SEVERITIES,
        default="high",
        help="Gate threshold: exit 1 if a finding at/above this severity survives (default: high).",
    )
    scan_p.add_argument("--timeout", type=float, default=10.0, help="Per-call timeout seconds.")
    scan_p.add_argument(
        "--transport", choices=["stdio", "streamable_http"], default="stdio",
        help="MCP transport (default: stdio).",
    )
    scan_p.add_argument("--json", action="store_true", help="Emit machine JSON to stdout.")
    scan_p.add_argument("--output", metavar="DIR", help="Also write report.json + report.html here.")
    return parser


def main(argv: list[str] | None = None, *, connect: Connect = _default_connect) -> int:
    """Parse args and dispatch to :func:`run_scan`. Usage errors exit 2 (argparse)."""
    args = _parser().parse_args(argv)
    return run_scan(
        args.target,
        fail_on=args.fail_on,
        timeout=args.timeout,
        transport=args.transport,
        json_out=args.json,
        output_dir=args.output,
        connect=connect,
    )


def _console() -> None:
    """Console-script entry point (`provenire`)."""
    raise SystemExit(main())


__all__ = ["run_scan", "main", "_default_connect"]
