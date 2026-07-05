"""§2.2 — the Finding model."""

from __future__ import annotations

import dataclasses

import pytest

from provenire_engine import Finding


def test_finding_fields_in_spec_order() -> None:
    f = Finding("tool.poisoning", "tool:x", "high", 0.85, "why")
    assert [fld.name for fld in dataclasses.fields(f)] == [
        "finding_type",
        "entity_ref",
        "severity",
        "confidence",
        "rationale",
    ]
    assert f.finding_type == "tool.poisoning"
    assert f.entity_ref == "tool:x"
    assert f.severity == "high"
    assert f.confidence == 0.85
    assert f.rationale == "why"


def test_finding_is_frozen() -> None:
    f = Finding("t", "e", "low", 0.1, "r")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.severity = "high"  # type: ignore[misc]
