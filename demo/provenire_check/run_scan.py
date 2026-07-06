"""Act 2 — drive the REAL Provenire pipeline over the malicious server.

Calls the shipped engine + control_plane functions exactly as their unit tests
do (signatures confirmed against source + ``packages/*/tests/``). The demo is a
*consumer*: it reimplements nothing and mutates no package code.

Pipeline:
    scan (async)            -> Manifest
    detect_poisoning/…      -> list[Finding]
    score_findings          -> ScanResult
    build_report            -> Report(.json/.html)      -> out/report.{json,html}
    load_baseline           -> Pack
    evaluate_pack           -> EvaluationResult
    build_evidence          -> Evidence(.json)          -> out/evidence.json
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from provenire_engine import (
    Finding,
    build_report,
    detect_over_privilege,
    detect_poisoning,
    scan,
    score_findings,
)
from provenire_control_plane.evidence.bundle import build_evidence
from provenire_control_plane.mapping.evaluate import evaluate_pack
from provenire_control_plane.mapping.pack import load_baseline

from provenire_check.fake_session import FakeSession

# Every finding_type the two detectors evaluate. Passing the full set lets
# evaluate_pack report clean controls as an honest "pass" (M8) rather than
# "not_applicable" (M9). Mirrors ALL_TYPES in the control_plane mapping tests.
EVALUATED_TYPES: set[str] = {
    "tool.poisoning",
    "tool.invisible_unicode",
    "tool.exfiltration",
    "tool.over_privilege",
    "tool.missing_schema",
    "tool.unbounded_schema",
}

_OUT_DIR = Path(__file__).resolve().parent.parent / "out"

# Fixed provenance for reproducible (byte-identical) evidence in --safe-mode /
# CI. Live runs stamp the real UTC time instead.
_FIXED_GENERATED_AT = "2026-07-05T00:00:00Z"


@dataclass(frozen=True)
class ScanOutcome:
    """What Act 2 produced — enough for the runner to narrate + self-check."""

    findings: tuple[Finding, ...]
    gate: str
    worst: str | None
    report_path: Path
    report_html_path: Path
    evidence_path: Path
    controls: tuple[tuple[str, str, str], ...]  # (id, title, state)


async def run_scan(*, deterministic: bool = False) -> ScanOutcome:
    """Run the full engine + control_plane pipeline; write artifacts to out/."""
    session = FakeSession()

    # --- Engine: scan -> detect -> score -> report -------------------------
    manifest = await scan(session, transport="stdio")
    findings = detect_poisoning(manifest) + detect_over_privilege(manifest)
    result = score_findings(findings)  # default floor 0.5 keeps 0.85 / 0.8 hits
    report = build_report(manifest, result)

    # --- Control plane: pack -> evaluate -> evidence -----------------------
    pack = load_baseline()
    evaluation = evaluate_pack(pack, result.findings, evaluated_types=EVALUATED_TYPES)

    generated_at = (
        _FIXED_GENERATED_AT
        if deterministic
        else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    # scan_id is derived from the manifest hash so evidence is tied to *this*
    # server and stays deterministic across identical runs.
    scan_id = "scn_" + manifest.manifest_hash.removeprefix("sha256:")[:12]
    evidence = build_evidence(
        manifest,
        result,
        evaluation,
        generated_at=generated_at,
        scan_id=scan_id,
    )

    # --- Persist artifacts (the engine returns strings; writing is our job) -
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = _OUT_DIR / "report.json"
    report_html_path = _OUT_DIR / "report.html"
    evidence_path = _OUT_DIR / "evidence.json"
    report_path.write_text(_pretty(report.json), encoding="utf-8")
    report_html_path.write_text(report.html, encoding="utf-8")
    evidence_path.write_text(_pretty(evidence.json), encoding="utf-8")

    return ScanOutcome(
        findings=result.findings,
        gate=result.score.gate,
        worst=result.score.worst,
        report_path=report_path,
        report_html_path=report_html_path,
        evidence_path=evidence_path,
        controls=tuple((c.id, c.title, c.state) for c in evaluation.results),
    )


def _pretty(compact_json: str) -> str:
    """Re-indent the engine's canonical compact JSON for a readable artifact."""
    return json.dumps(json.loads(compact_json), indent=2, ensure_ascii=True) + "\n"
