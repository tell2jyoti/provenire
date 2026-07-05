"""Mapping engine — apply a pack to a scan's findings (mapping-pack-spec §4, M7-M12).

Produces one `ControlState` per control: `fail` if a mapped finding is present
(M7); `pass` only if the control's types were actually evaluated by the scan and
none present (M8); `not_applicable` if none of its types were evaluated (M9). The
`pass`/`not_applicable` split is deliberate — a control is **never** reported as
passing for a check that did not run (honest N/A). The `evaluated_types` set is
injected (the engine has no taxonomy registry yet; mapping-pack-spec OQ-1). Output
is deterministic: results in pack order, breaching types sorted (M12).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from provenire_engine import Finding

from .pack import Pack, PackRef

ControlState = Literal["pass", "fail", "not_applicable"]


@dataclass(frozen=True)
class ControlResult:
    """One control's outcome. `breaching_types` is the evidence F9 cites (M10)."""

    id: str
    title: str
    state: ControlState
    breaching_types: tuple[str, ...]  # sorted; empty unless state == "fail"


@dataclass(frozen=True)
class EvaluationResult:
    """All control outcomes for a scan, plus the pack they came from (M10-M11)."""

    pack_ref: PackRef
    results: tuple[ControlResult, ...]


def evaluate_pack(
    pack: Pack, findings: Sequence[Finding], *, evaluated_types: set[str]
) -> EvaluationResult:
    """Evaluate `pack` against a scan's `findings` + the types it evaluated (M7-M12)."""
    present = {f.finding_type for f in findings}
    results: list[ControlResult] = []
    for control in pack.controls:
        breaching = tuple(sorted(t for t in control.breached_by if t in present))
        state: ControlState
        if breaching:
            state = "fail"  # M7 — a mapped finding is present
        elif any(t in evaluated_types for t in control.breached_by):
            state = "pass"  # M8 — evaluated and clean
        else:
            state = "not_applicable"  # M9 — never evaluated; don't fake a pass
        results.append(ControlResult(control.id, control.title, state, breaching))
    return EvaluationResult(pack.pack, tuple(results))


__all__ = ["ControlState", "ControlResult", "EvaluationResult", "evaluate_pack"]
