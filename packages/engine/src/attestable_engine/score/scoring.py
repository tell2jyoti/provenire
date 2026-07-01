"""Scoring (§4, feature F4, layer: engine).

Deterministic, no-LLM post-detection stage. Takes the combined ``list[Finding]``
from every §3.2+ detector and normalizes the *provisional* severity/confidence
they set into a stable, report-ready ranking + summary that F5 (report) and F6
(CLI ``--fail-on``) consume:

- **S2** clamp each ``confidence`` into ``[0, 1]`` (a new frozen ``Finding``;
  the input is never mutated);
- **S3** suppress any finding strictly below ``confidence_floor`` (removed
  entirely — absent from findings *and* the aggregate);
- **S1/S4** order survivors highest-risk-first by
  ``(rank desc, confidence desc, entity_ref asc, finding_type asc)`` — severity
  is used for its total order but never rewritten (context escalation is F8);
- **S5** summarize survivors into a ``ScanScore`` (per-severity counts, worst,
  pass/fail gate).

Pure function of ``(findings, confidence_floor, gate_threshold)``: no clock, no
randomness, no input-order dependence, idempotent. It names no regulation
(architecture law); mapping lives in ``control_plane/packs/*.yaml``.
"""

from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass
from typing import Literal

from ..finding import Finding, Severity

# S1 — the fixed total order over the four §2.2 severities. A scoring internal:
# it is NOT stored on Finding (the §2.2 five-field contract is frozen).
_RANK: dict[Severity, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class ScanScore:
    """S5 aggregate over the surviving findings."""

    # All four severity keys are always present (0 when none at that level).
    counts: dict[Severity, int]
    # Highest surviving severity, or None when there are no survivors.
    worst: Severity | None
    # "fail" iff a survivor is at/above gate_threshold, else "pass".
    gate: Literal["pass", "fail"]


@dataclass(frozen=True)
class ScanResult:
    """The output of scoring: risk-ordered survivors + their aggregate."""

    findings: tuple[Finding, ...]
    score: ScanScore


def _clamp_confidence(finding: Finding) -> Finding:
    # S2: confidence is contractually a probability. Normalize into [0, 1] — NaN
    # (not a probability, and `NaN >= floor` is always False, so it would silently
    # vanish at S3) maps to 0.0 explicitly rather than relying on min/max's
    # argument-order behavior. Returns the *same* finding when already in range;
    # only out-of-range values allocate a new frozen copy (input never mutated).
    c = finding.confidence
    if math.isnan(c):
        clamped = 0.0
    else:
        clamped = min(1.0, max(0.0, c))
    if clamped == c:
        return finding
    return dataclasses.replace(finding, confidence=clamped)


def score_findings(
    findings: list[Finding],
    *,
    confidence_floor: float = 0.5,
    gate_threshold: Severity = "high",
) -> ScanResult:
    """Return a :class:`ScanResult` per spec §4 (rules S0–S5)."""
    # S2 then S3: clamp, then drop anything strictly below the floor.
    survivors = [
        f for f in map(_clamp_confidence, findings) if f.confidence >= confidence_floor
    ]

    # S4: highest-risk first, with a total-order tiebreak that stays consistent
    # with the detectors' canonical (entity_ref, finding_type) ordering — so the
    # result is deterministic and independent of input order.
    survivors.sort(key=lambda f: (f.entity_ref, f.finding_type))
    survivors.sort(key=lambda f: (_RANK[f.severity], f.confidence), reverse=True)

    # S5: aggregate over survivors.
    counts: dict[Severity, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in survivors:
        counts[f.severity] += 1
    worst = max((f.severity for f in survivors), key=_RANK.__getitem__, default=None)
    threshold_rank = _RANK[gate_threshold]
    gate: Literal["pass", "fail"] = (
        "fail" if any(_RANK[f.severity] >= threshold_rank for f in survivors) else "pass"
    )

    return ScanResult(tuple(survivors), ScanScore(counts, worst, gate))


__all__ = ["ScanResult", "ScanScore", "score_findings"]
