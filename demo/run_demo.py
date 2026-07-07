"""Provenire demo runner (§7) — "watch it break, then watch us catch it".

Runs two acts over the SAME malicious MCP server:

- ACT 1 (without Provenire): a compromised agent obeys a poisoned tool
  description, reads the decoy secret, and hands it to a local mock sink.
- ACT 2 (with Provenire): the identical server's tool definitions go through
  Provenire's real engine + control_plane, which flags the exact tool that
  leaked in Act 1 and writes a real evidence record.

Usage:
    python demo/run_demo.py              # live Act 1 if deps+key present, else safe-mode
    python demo/run_demo.py --safe-mode  # deterministic, no LLM, CI/recording
    python demo/run_demo.py --act 2      # one act only
    python demo/run_demo.py --json       # machine-readable output

Exit code is non-zero if Act 2 fails to flag the poisoned tool — so the demo
doubles as a self-check (§7).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from agent.app import Act1Trace, run_live, run_safe_mode
from agent.mcp_client import LiveModeUnavailable
from malicious_server.tools import DECOY_SECRET, TOOLS
from provenire_check.run_scan import ScanOutcome, run_scan

# The two findings Act 2 must produce for the demo's thesis to hold (§9).
_REQUIRED = {"tool.poisoning", "tool.exfiltration"}

_RULE = "─" * 66


def _banner(title: str) -> None:
    print(f"\n{_RULE}\n── {title} ──\n{_RULE}")


# --- Act 1 -----------------------------------------------------------------


def _run_act1(*, safe_mode: bool) -> Act1Trace:
    """Run Act 1, preferring the live LLM break but falling back cleanly."""
    if safe_mode:
        return run_safe_mode()
    try:
        return run_live()
    except LiveModeUnavailable as exc:
        print(f"   (live mode unavailable: {exc})")
        print("   falling back to --safe-mode (deterministic reproduction)\n")
        return run_safe_mode()


def _print_act1(trace: Act1Trace) -> None:
    print(f"\n   mode          : {trace.mode}")
    print(f'   user asked    : "{trace.user_message}"')
    print(f"   agent chose   : {trace.chosen_tool}({_fmt_args(trace.tool_args)})")
    print(f"   decoy in args : units = {trace.tool_args.get('units', '<none>')!r}")
    # The mock sink already printed its RECEIVED line as the payload arrived.
    if trace.leaked:
        print("\n   ⚠️  The agent leaked a secret it was never asked to touch.")
    else:
        print("\n   (no leak this run — LLM did not obey; try --safe-mode)")


def _fmt_args(args: dict[str, str]) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


# --- Act 2 -----------------------------------------------------------------


def _print_act2(outcome: ScanOutcome) -> None:
    by_entity = {f.entity_ref: f for f in outcome.findings}
    print("\n   findings:")
    for tool in TOOLS:
        finding = by_entity.get(f"tool:{tool.name}")
        if finding is None:
            print(f"     • {tool.name:<13} → clean")
        else:
            print(
                f"     • {tool.name:<13} → {finding.finding_type} · "
                f"{finding.severity.upper()}"
            )
    print(f"\n   gate          : {outcome.gate}   (worst: {outcome.worst})")
    print(f"   report.json   : {outcome.report_path}")
    print(f"   evidence.json : {outcome.evidence_path}")
    print(
        "\n   ✅  The tool that leaked your secret in Act 1 is the one Provenire\n"
        "       flagged in Act 2 — the scan would have caught it before the\n"
        "       agent ever connected."
    )


# --- JSON surface (--json) -------------------------------------------------


def _json_payload(
    trace: Act1Trace | None, outcome: ScanOutcome | None
) -> dict[str, object]:
    payload: dict[str, object] = {}
    if trace is not None:
        payload["act1"] = {
            "mode": trace.mode,
            "user_message": trace.user_message,
            "chosen_tool": trace.chosen_tool,
            "tool_args": trace.tool_args,
            "leaked": trace.leaked,
            "decoy": DECOY_SECRET,
        }
    if outcome is not None:
        payload["act2"] = {
            "findings": [
                {
                    "entity_ref": f.entity_ref,
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in outcome.findings
            ],
            "gate": outcome.gate,
            "worst": outcome.worst,
            "report_path": str(outcome.report_path),
            "evidence_path": str(outcome.evidence_path),
            "controls": [
                {"id": cid, "title": title, "state": state}
                for cid, title, state in outcome.controls
            ],
        }
    return payload


def _act2_flagged_required(outcome: ScanOutcome) -> bool:
    return _REQUIRED <= {f.finding_type for f in outcome.findings}


# --- Entrypoint ------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provenire two-act demo.")
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="deterministic Act 1 with no LLM call (CI / recording).",
    )
    parser.add_argument(
        "--act",
        choices=("1", "2"),
        help="run only one act (default: both).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit machine-readable JSON instead of the narrative.",
    )
    args = parser.parse_args(argv)

    run_act1 = args.act in (None, "1")
    run_act2 = args.act in (None, "2")
    # Deterministic evidence whenever Act 1 didn't take the live path.
    deterministic = args.safe_mode or args.act == "2"

    trace: Act1Trace | None = None
    outcome: ScanOutcome | None = None

    if not args.as_json and run_act1:
        _banner("ACT 1 · WITHOUT PROVENIRE")
    if run_act1:
        trace = _run_act1(safe_mode=args.safe_mode)
        if not args.as_json:
            _print_act1(trace)

    if not args.as_json and run_act2:
        _banner("ACT 2 · WITH PROVENIRE")
    if run_act2:
        outcome = asyncio.run(run_scan(deterministic=deterministic))
        if not args.as_json:
            _print_act2(outcome)

    if args.as_json:
        print(json.dumps(_json_payload(trace, outcome), indent=2))

    # Self-check (§7): Act 2, when run, must flag the poisoned + exfil tools.
    if outcome is not None and not _act2_flagged_required(outcome):
        missing = _REQUIRED - {f.finding_type for f in outcome.findings}
        print(f"\n✗ self-check FAILED: Act 2 did not flag {sorted(missing)}", file=sys.stderr)
        return 1

    if not args.as_json and run_act1 and run_act2:
        _banner("VERDICT")
        print(
            "\n   Act 1: the agent leaked the decoy through a poisoned tool.\n"
            "   Act 2: Provenire flagged that exact tool — before connection.\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
