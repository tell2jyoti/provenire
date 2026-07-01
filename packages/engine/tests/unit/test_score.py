"""§4 — scoring (feature F4). Rules S0–S5.

Scoring is a pure post-detection stage over a ``list[Finding]``: clamp
confidence (S2), suppress below a floor (S3), rank into a deterministic
highest-risk-first order (S4), and summarize into a ``ScanScore`` (S5). It
never rewrites severity (S1) and is empty-in/empty-out (S0). No manifest, no
network — findings are constructed directly.
"""

from __future__ import annotations

import dataclasses

import pytest

from attestable_engine import Finding
from attestable_engine.score import ScanResult, ScanScore, score_findings


def _f(
    finding_type: str = "tool.poisoning",
    entity_ref: str = "tool:x",
    severity: str = "high",
    confidence: float = 0.8,
    rationale: str = "why",
) -> Finding:
    """A Finding builder with spec-plausible defaults (severity typed loosely for tests)."""
    return Finding(finding_type, entity_ref, severity, confidence, rationale)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- S0
def test_s0_empty_findings_returns_empty_result() -> None:
    result = score_findings([])
    assert result.findings == ()
    assert result.score.counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert result.score.worst is None
    assert result.score.gate == "pass"


def test_s0_all_suppressed_yields_empty_result() -> None:
    # Every finding is below the default floor → indistinguishable from empty.
    result = score_findings([_f(confidence=0.1), _f(confidence=0.4)])
    assert result.findings == ()
    assert result.score.counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert result.score.worst is None
    assert result.score.gate == "pass"


# --------------------------------------------------------------------------- S1
@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
def test_s1_severity_preserved(severity: str) -> None:
    # S1: scoring uses the order to rank/aggregate but never rewrites severity.
    result = score_findings([_f(severity=severity, confidence=0.9)])
    assert result.findings[0].severity == severity


# --------------------------------------------------------------------------- S2
def test_s2_negative_confidence_clamped_to_zero() -> None:
    # Clamped to 0.0 → below default floor → suppressed; assert with floor=0.0 to observe it.
    result = score_findings([_f(confidence=-0.5)], confidence_floor=0.0)
    assert result.findings[0].confidence == 0.0


def test_s2_over_one_confidence_clamped_to_one() -> None:
    result = score_findings([_f(confidence=1.5)])
    assert result.findings[0].confidence == 1.0


def test_s2_in_range_confidence_unchanged() -> None:
    result = score_findings([_f(confidence=0.75)])
    assert result.findings[0].confidence == 0.75


def test_s2_zero_boundary_unchanged() -> None:
    result = score_findings([_f(confidence=0.0)], confidence_floor=0.0)
    assert result.findings[0].confidence == 0.0


def test_s2_one_boundary_unchanged() -> None:
    result = score_findings([_f(confidence=1.0)])
    assert result.findings[0].confidence == 1.0


def test_s2_clamping_creates_new_finding_input_untouched() -> None:
    original = _f(confidence=1.5)
    result = score_findings([original])
    assert original.confidence == 1.5  # input never mutated
    assert result.findings[0] is not original  # clamp yields a new frozen Finding
    assert result.findings[0].confidence == 1.0


def test_s2_nan_confidence_clamped_to_zero() -> None:
    # S2 mandates a value in [0,1]; NaN is not a probability. It must clamp to
    # 0.0 (not pass through — else `NaN >= floor` is False and it vanishes,
    # silently hiding a finding). floor=0.0 so we can observe the clamped value.
    result = score_findings([_f(confidence=float("nan"))], confidence_floor=0.0)
    assert result.findings[0].confidence == 0.0


def test_s2_positive_inf_clamped_to_one() -> None:
    result = score_findings([_f(confidence=float("inf"))])
    assert result.findings[0].confidence == 1.0


def test_s2_negative_inf_clamped_to_zero() -> None:
    result = score_findings([_f(confidence=float("-inf"))], confidence_floor=0.0)
    assert result.findings[0].confidence == 0.0


# --------------------------------------------------------------------------- S3
def test_s3_below_floor_removed_from_findings() -> None:
    result = score_findings([_f(confidence=0.3)])  # default floor 0.5
    assert result.findings == ()


def test_s3_equal_floor_kept() -> None:
    # Strictly-below is dropped; == floor is kept.
    result = score_findings([_f(confidence=0.5)], confidence_floor=0.5)
    assert len(result.findings) == 1


def test_s3_above_floor_kept() -> None:
    result = score_findings([_f(confidence=0.7)], confidence_floor=0.5)
    assert len(result.findings) == 1


def test_s3_custom_floor_suppresses_below() -> None:
    result = score_findings([_f(confidence=0.6)], confidence_floor=0.7)
    assert result.findings == ()


def test_s3_custom_floor_keeps_at_floor() -> None:
    result = score_findings([_f(confidence=0.7)], confidence_floor=0.7)
    assert len(result.findings) == 1


def test_s3_suppressed_not_in_counts() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:a", confidence=0.9),
            _f(severity="critical", entity_ref="tool:b", confidence=0.9),
            _f(severity="high", entity_ref="tool:c", confidence=0.2),  # suppressed
        ]
    )
    assert result.score.counts == {"critical": 2, "high": 0, "medium": 0, "low": 0}


def test_s3_suppressed_not_in_worst() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:a", confidence=0.2),  # suppressed
            _f(severity="medium", entity_ref="tool:b", confidence=0.9),
        ]
    )
    assert result.score.worst == "medium"


def test_s3_suppressed_not_in_gate() -> None:
    result = score_findings(
        [_f(severity="critical", confidence=0.2)],  # suppressed
        gate_threshold="critical",
    )
    assert result.score.gate == "pass"


# --------------------------------------------------------------------------- S4
@pytest.mark.parametrize(
    ("lower", "higher"),
    [("high", "critical"), ("medium", "high"), ("low", "medium")],
)
def test_s4_higher_rank_first(lower: str, higher: str) -> None:
    result = score_findings(
        [
            _f(severity=lower, entity_ref="tool:a", confidence=0.9),
            _f(severity=higher, entity_ref="tool:b", confidence=0.9),
        ]
    )
    assert [f.severity for f in result.findings] == [higher, lower]


def test_s4_tied_rank_higher_confidence_first() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:a", confidence=0.7),
            _f(severity="critical", entity_ref="tool:b", confidence=0.9),
        ]
    )
    assert [f.confidence for f in result.findings] == [0.9, 0.7]


def test_s4_tied_rank_confidence_entity_ref_asc() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:z", confidence=0.9),
            _f(severity="critical", entity_ref="tool:a", confidence=0.9),
        ]
    )
    assert [f.entity_ref for f in result.findings] == ["tool:a", "tool:z"]


def test_s4_all_tied_finding_type_asc() -> None:
    result = score_findings(
        [
            _f(finding_type="tool.zeta", entity_ref="tool:a", severity="high", confidence=0.9),
            _f(finding_type="tool.alpha", entity_ref="tool:a", severity="high", confidence=0.9),
        ]
    )
    assert [f.finding_type for f in result.findings] == ["tool.alpha", "tool.zeta"]


def test_s4_input_order_independence() -> None:
    findings = [
        _f(severity="low", entity_ref="tool:a", confidence=0.9),
        _f(severity="critical", entity_ref="tool:b", confidence=0.9),
        _f(severity="medium", entity_ref="tool:c", confidence=0.9),
    ]
    forward = score_findings(findings)
    reverse = score_findings(list(reversed(findings)))
    assert forward == reverse
    assert [f.severity for f in forward.findings] == ["critical", "medium", "low"]


def test_s4_deterministic_same_input_same_output() -> None:
    findings = [
        _f(severity="high", entity_ref="tool:a", confidence=0.9),
        _f(severity="critical", entity_ref="tool:b", confidence=0.9),
    ]
    assert score_findings(findings) == score_findings(findings)


def test_s4_idempotent_score_a_scored_result() -> None:
    findings = [
        _f(severity="high", entity_ref="tool:a", confidence=0.9),
        _f(severity="critical", entity_ref="tool:b", confidence=0.6),
        _f(severity="low", entity_ref="tool:c", confidence=0.55),
    ]
    once = score_findings(findings)
    twice = score_findings(list(once.findings))
    assert once == twice


# --------------------------------------------------------------------------- S5
def test_s5_counts_all_four_keys_present() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:a", confidence=0.9),
            _f(severity="high", entity_ref="tool:b", confidence=0.9),
        ]
    )
    assert set(result.score.counts) == {"critical", "high", "medium", "low"}


def test_s5_counts_zero_when_none_at_level() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:a", confidence=0.9),
            _f(severity="high", entity_ref="tool:b", confidence=0.9),
        ]
    )
    assert result.score.counts["medium"] == 0
    assert result.score.counts["low"] == 0


def test_s5_counts_correct_totals() -> None:
    result = score_findings(
        [
            _f(severity="critical", entity_ref="tool:a", confidence=0.9),
            _f(severity="critical", entity_ref="tool:b", confidence=0.9),
            _f(severity="high", entity_ref="tool:c", confidence=0.9),
            _f(severity="low", entity_ref="tool:d", confidence=0.9),
        ]
    )
    assert result.score.counts == {"critical": 2, "high": 1, "medium": 0, "low": 1}


def test_s5_worst_is_highest_survivor_severity() -> None:
    result = score_findings(
        [
            _f(severity="low", entity_ref="tool:a", confidence=0.9),
            _f(severity="high", entity_ref="tool:b", confidence=0.9),
            _f(severity="medium", entity_ref="tool:c", confidence=0.9),
        ]
    )
    assert result.score.worst == "high"


def test_s5_worst_none_when_empty() -> None:
    assert score_findings([]).score.worst is None


def test_s5_gate_fail_at_threshold() -> None:
    result = score_findings([_f(severity="high", confidence=0.9)], gate_threshold="high")
    assert result.score.gate == "fail"


def test_s5_gate_fail_above_threshold() -> None:
    result = score_findings([_f(severity="critical", confidence=0.9)], gate_threshold="high")
    assert result.score.gate == "fail"


def test_s5_gate_pass_below_threshold() -> None:
    result = score_findings([_f(severity="medium", confidence=0.9)], gate_threshold="high")
    assert result.score.gate == "pass"


def test_s5_gate_pass_when_empty() -> None:
    assert score_findings([]).score.gate == "pass"


def test_s5_gate_threshold_critical() -> None:
    result = score_findings([_f(severity="high", confidence=0.9)], gate_threshold="critical")
    assert result.score.gate == "pass"


def test_s5_gate_threshold_medium() -> None:
    result = score_findings([_f(severity="high", confidence=0.9)], gate_threshold="medium")
    assert result.score.gate == "fail"


def test_s5_gate_threshold_low() -> None:
    result = score_findings([_f(severity="medium", confidence=0.9)], gate_threshold="low")
    assert result.score.gate == "fail"


# ------------------------------------------------------------------- types + F4
def test_types_are_frozen() -> None:
    result = score_findings([_f(confidence=0.9)])
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.score.gate = "pass"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.findings = ()  # type: ignore[misc]


def test_f4_acceptance_comprehensive() -> None:
    # Mixed severities/confidences (some needing clamp), some suppressed, shuffled.
    findings = [
        _f(severity="low", entity_ref="tool:d", confidence=0.55),
        _f(severity="critical", entity_ref="tool:a", confidence=1.5),  # clamps to 1.0
        _f(severity="high", entity_ref="tool:c", confidence=0.2),  # suppressed (< 0.5)
        _f(severity="high", entity_ref="tool:b", confidence=0.9),
        _f(severity="medium", entity_ref="tool:e", confidence=-0.1),  # clamps to 0.0, suppressed
    ]
    result = score_findings(findings)

    # Survivors: critical(1.0), high(0.9), low(0.55) — risk-ordered.
    assert [(f.severity, f.entity_ref) for f in result.findings] == [
        ("critical", "tool:a"),
        ("high", "tool:b"),
        ("low", "tool:d"),
    ]
    assert result.findings[0].confidence == 1.0  # clamped
    assert result.score.counts == {"critical": 1, "high": 1, "medium": 0, "low": 1}
    assert result.score.worst == "critical"
    assert result.score.gate == "fail"  # critical ≥ high default threshold
    assert isinstance(result, ScanResult)
    assert isinstance(result.score, ScanScore)
    # Input-order-independent.
    assert score_findings(list(reversed(findings))) == result
