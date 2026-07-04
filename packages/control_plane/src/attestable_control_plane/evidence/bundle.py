"""Evidence builder (evidence-export-spec §2-§5, rules EV1-EV13).

Assembles a scan's structured outputs — the Manifest (F1), the scored ScanResult
(F4), and the pack EvaluationResult (F8) — plus caller-supplied provenance into a
single self-contained, deterministic evidence document. It is the compliance
record: which pack (id+version) judged which controls over which findings.

Design mirrors F5's `build_report`: a **pure** function (no clock, no RNG, no I/O)
returning a frozen value whose `.json` is the deterministic artifact a caller
persists or signs later. Provenance (`generated_at`, `scan_id`) is injected, never
generated here (EV11). Finding text is recorded **verbatim** (JSON-escaped by the
encoder), never stripped of control bytes — evidence must be faithful (EV13),
unlike the terminal/HTML surfaces which strip for rendering safety.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from attestable_engine import Finding, Manifest, ScanResult
from attestable_engine.finding import Severity

from ..mapping.evaluate import ControlResult, EvaluationResult

_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class Evidence:
    """The deterministic evidence document (EV9). `.json` is the signable artifact."""

    json: str


def build_evidence(
    manifest: Manifest,
    result: ScanResult,
    evaluation: EvaluationResult,
    *,
    generated_at: str,
    scan_id: str,
    schema_version: str = "1.0",
) -> Evidence:
    """Build the evidence document from a scan's outputs + provenance (EV1-EV13).

    Pure and deterministic: identical inputs (incl. `generated_at`/`scan_id`) yield
    a byte-identical `.json`.
    """
    payload = _payload(manifest, result, evaluation, generated_at, scan_id, schema_version)
    # EV12: sorted keys + compact separators → deterministic, no incidental whitespace.
    return Evidence(json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")))


def _payload(
    manifest: Manifest, result: ScanResult, evaluation: EvaluationResult,
    generated_at: str, scan_id: str, schema_version: str,
) -> dict[str, Any]:
    score = result.score
    return {
        "schema_version": schema_version,
        "generated_at": generated_at,  # EV11 — injected verbatim
        "scan_id": scan_id,            # EV11 — injected verbatim
        "pack": {"id": evaluation.pack_ref.id, "version": evaluation.pack_ref.version},  # EV2
        "server": {"manifest_hash": manifest.manifest_hash, "transport": manifest.transport},  # EV3
        "summary": {  # EV4
            "counts": {sev: score.counts[sev] for sev in _SEVERITIES},
            "worst": score.worst,
            "gate": score.gate,
        },
        "controls": [_control_dict(c) for c in evaluation.results],  # EV5, in order
        "findings": [_finding_dict(f) for f in result.findings],     # EV6, in order
    }


def _control_dict(control: ControlResult) -> dict[str, Any]:
    return {
        "id": control.id,
        "title": control.title,
        "state": control.state,
        "breaching_types": list(control.breaching_types),  # sorted; empty unless fail
    }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    # EV13 — verbatim (JSON-escaped), never stripped: evidence must be faithful.
    return {
        "finding_type": finding.finding_type,
        "entity_ref": finding.entity_ref,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "rationale": finding.rationale,
    }


__all__ = ["Evidence", "build_evidence"]
