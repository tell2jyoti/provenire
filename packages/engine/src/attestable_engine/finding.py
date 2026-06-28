"""Finding model (§2.2).

The output of every detection rule from §3.2 onward. §3.1 (connect & enumerate)
emits a `Manifest` and no `Finding`s. Frozen so a produced finding cannot be
mutated after the fact (scores are normalized into *new* findings by §4/F4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# §2.2 severity enum — a Literal so mypy --strict flags a mistyped severity at
# the detector call sites, where this product's value lives.
Severity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True)
class Finding:
    # Field order is part of the §2.2 contract (test_finding_fields_in_spec_order).
    finding_type: str
    entity_ref: str
    severity: Severity
    confidence: float
    rationale: str
