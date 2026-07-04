"""mapping-pack-spec — F8 mapping engine + baseline pack (control_plane, COMMERCIAL).

Rules M1-M14 (pack format + mapping-engine semantics), B0-B5 (baseline pack
content). Every test cites the rule it derives from. The pack is data, not code:
`finding_type`s (framework-neutral, from the engine) map to vendor-neutral
controls in `packs/*.yaml`; no regulation is named in code (architecture law).
control_plane imports `attestable_engine` (allowed); nothing here imports cli.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from attestable_engine import Finding

from attestable_control_plane.mapping.evaluate import (
    ControlResult,
    EvaluationResult,
    evaluate_pack,
)
from attestable_control_plane.mapping.pack import (
    Control,
    Pack,
    PackError,
    PackRef,
    load_baseline,
    load_pack,
)

# The six framework-neutral finding_types the engine emits (spec §M6).
ALL_TYPES = {
    "tool.poisoning",
    "tool.invisible_unicode",
    "tool.exfiltration",
    "tool.over_privilege",
    "tool.missing_schema",
    "tool.unbounded_schema",
}


# --- helpers ---------------------------------------------------------------
def _pack_yaml(controls: Iterable[tuple[str, list[str]]], *, pack_id: str = "test",
               version: int = 1) -> str:
    """Build a minimal valid pack YAML from (control_id, breached_by) pairs."""
    lines = [f"pack:\n  id: {pack_id}\n  version: {version}\ncontrols:"]
    for cid, types in controls:
        arr = ", ".join(types)
        lines.append(f"  - id: {cid}\n    title: {cid} title\n    breached_by: [{arr}]")
    return "\n".join(lines) + "\n"


def _one_control_pack(cid: str, types: list[str]) -> Pack:
    return load_pack(_pack_yaml([(cid, types)]))


def _finding(finding_type: str, entity_ref: str = "tool:x") -> Finding:
    return Finding(finding_type, entity_ref, "high", 0.9, "rationale")


_VALID_MINIMAL = _pack_yaml([("C1", ["tool.poisoning"])])


# ===========================================================================
# Group A — Pack loading & validation (M1-M4). Fails closed.
# ===========================================================================
def test_load_pack_valid_minimal() -> None:  # M1/M2
    pack = load_pack(_VALID_MINIMAL)
    assert isinstance(pack, Pack)
    assert pack.pack == PackRef("test", 1)
    assert pack.controls == (Control("C1", "C1 title", ("tool.poisoning",)),)


def test_load_pack_missing_pack_key() -> None:  # M3
    text = "controls:\n  - id: C1\n    title: t\n    breached_by: [tool.poisoning]\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_missing_controls_key() -> None:  # M3
    with pytest.raises(PackError):
        load_pack("pack:\n  id: test\n  version: 1\n")


def test_load_pack_not_a_mapping() -> None:  # M1/M3
    with pytest.raises(PackError):
        load_pack("- a\n- b\n")


def test_load_pack_controls_not_list() -> None:  # M3
    text = "pack:\n  id: t\n  version: 1\ncontrols:\n  id: C1\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_empty_controls_list() -> None:  # M1/M3
    with pytest.raises(PackError):
        load_pack("pack:\n  id: t\n  version: 1\ncontrols: []\n")


def test_load_pack_missing_control_id() -> None:  # M2/M3
    text = "pack:\n  id: t\n  version: 1\ncontrols:\n  - title: t\n    breached_by: [tool.poisoning]\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_missing_control_title() -> None:  # M2/M3
    text = "pack:\n  id: t\n  version: 1\ncontrols:\n  - id: C1\n    breached_by: [tool.poisoning]\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_missing_breached_by() -> None:  # M2/M3
    text = "pack:\n  id: t\n  version: 1\ncontrols:\n  - id: C1\n    title: t\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_control_id_empty_string() -> None:  # M2
    with pytest.raises(PackError):
        load_pack(_pack_yaml([("", ["tool.poisoning"])]))


def test_load_pack_control_title_empty_string() -> None:  # M2
    text = 'pack:\n  id: t\n  version: 1\ncontrols:\n  - id: C1\n    title: ""\n    breached_by: [tool.poisoning]\n'
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_breached_by_empty_list() -> None:  # M2
    with pytest.raises(PackError):
        load_pack(_pack_yaml([("C1", [])]))


def test_load_pack_breached_by_not_list() -> None:  # M3
    text = "pack:\n  id: t\n  version: 1\ncontrols:\n  - id: C1\n    title: t\n    breached_by: tool.poisoning\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_duplicate_control_id() -> None:  # M3
    with pytest.raises(PackError):
        load_pack(_pack_yaml([("C1", ["tool.poisoning"]), ("C1", ["tool.exfiltration"])]))


def test_load_pack_non_string_in_breached_by() -> None:  # M3
    text = "pack:\n  id: t\n  version: 1\ncontrols:\n  - id: C1\n    title: t\n    breached_by: [123]\n"
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_version_zero_rejected() -> None:  # M13 (version >= 1)
    with pytest.raises(PackError):
        load_pack(_pack_yaml([("C1", ["tool.poisoning"])], version=0))


def test_load_pack_version_bool_rejected() -> None:  # M13 (bool is not a valid int version)
    text = ("pack:\n  id: t\n  version: true\ncontrols:\n  - id: C1\n    title: t\n"
            "    breached_by: [tool.poisoning]\n")
    with pytest.raises(PackError):
        load_pack(text)


def test_load_pack_unknown_top_level_keys_ignored() -> None:  # M1
    pack = load_pack(_VALID_MINIMAL + "extra_key: whatever\n")
    assert pack.pack.id == "test"


def test_load_pack_unknown_control_keys_ignored() -> None:  # M2
    text = ("pack:\n  id: t\n  version: 1\ncontrols:\n  - id: C1\n    title: t\n"
            "    breached_by: [tool.poisoning]\n    note: ignore me\n")
    pack = load_pack(text)
    assert pack.controls[0].id == "C1"


def test_load_pack_uses_safe_load_never_unsafe() -> None:  # M4
    # A python-object tag executes under yaml.load but must be rejected by safe_load.
    with pytest.raises(PackError):
        load_pack("!!python/object/apply:os.system ['echo pwned']\n")


# ===========================================================================
# Group B — Baseline pack location & content (B0-B5).
# ===========================================================================
def test_load_baseline_returns_valid_pack() -> None:
    assert isinstance(load_baseline(), Pack)


def test_baseline_pack_id_is_baseline() -> None:  # B0
    assert load_baseline().pack.id == "baseline"


def test_baseline_pack_version_is_1() -> None:  # B0
    assert load_baseline().pack.version == 1


def _baseline_control(cid: str) -> Control:
    for c in load_baseline().controls:
        if c.id == cid:
            return c
    raise AssertionError(f"control {cid} not in baseline")


def test_baseline_control_mcp_injection_exists() -> None:  # B1
    assert _baseline_control("MCP-INJECTION")


def test_baseline_control_mcp_injection_has_poisoning() -> None:  # B1
    assert "tool.poisoning" in _baseline_control("MCP-INJECTION").breached_by


def test_baseline_control_mcp_injection_has_invisible_unicode() -> None:  # B1
    assert "tool.invisible_unicode" in _baseline_control("MCP-INJECTION").breached_by


def test_baseline_control_mcp_exfil_exists() -> None:  # B2
    assert _baseline_control("MCP-EXFIL")


def test_baseline_control_mcp_exfil_has_exfiltration() -> None:  # B2
    assert "tool.exfiltration" in _baseline_control("MCP-EXFIL").breached_by


def test_baseline_control_mcp_leastpriv_exists() -> None:  # B3
    assert _baseline_control("MCP-LEASTPRIV")


def test_baseline_control_mcp_leastpriv_has_over_privilege() -> None:  # B3
    assert "tool.over_privilege" in _baseline_control("MCP-LEASTPRIV").breached_by


def test_baseline_control_mcp_schema_exists() -> None:  # B4
    assert _baseline_control("MCP-SCHEMA")


def test_baseline_control_mcp_schema_has_missing_schema() -> None:  # B4
    assert "tool.missing_schema" in _baseline_control("MCP-SCHEMA").breached_by


def test_baseline_control_mcp_schema_has_unbounded_schema() -> None:  # B4
    assert "tool.unbounded_schema" in _baseline_control("MCP-SCHEMA").breached_by


def test_baseline_control_ids_four_not_fewer() -> None:  # B1-B4
    assert len(load_baseline().controls) == 4


def test_baseline_covers_all_six_finding_types() -> None:  # B5
    mapped = {t for c in load_baseline().controls for t in c.breached_by}
    assert mapped == ALL_TYPES


def test_baseline_control_ids_vendor_neutral() -> None:  # B5
    ids = " ".join(c.id for c in load_baseline().controls).upper()
    for regulation in ("HIPAA", "SOC2", "SOC 2", "PCI", "GDPR", "ISO"):
        assert regulation not in ids


# ===========================================================================
# Group C — ControlState logic (M7-M9).
# ===========================================================================
def _state(cid: str, types: list[str], findings: list[Finding],
           evaluated: set[str]) -> str:
    pack = _one_control_pack(cid, types)
    return evaluate_pack(pack, findings, evaluated_types=evaluated).results[0].state


def test_control_state_fail_when_finding_in_breached_by() -> None:  # M7
    assert _state("C1", ["tool.poisoning"], [_finding("tool.poisoning")], ALL_TYPES) == "fail"


def test_control_state_pass_when_no_finding_and_type_evaluated() -> None:  # M8
    assert _state("C1", ["tool.poisoning"], [], {"tool.poisoning"}) == "pass"


def test_control_state_not_applicable_when_type_not_evaluated() -> None:  # M9
    assert _state("C1", ["tool.poisoning"], [], set()) == "not_applicable"


def test_control_state_never_pass_when_unevaluated() -> None:  # M9
    # No finding + type not evaluated must NOT be reported as pass.
    assert _state("C1", ["tool.poisoning"], [], {"tool.exfiltration"}) != "pass"


def test_control_state_fail_with_multiple_breaching_types_present() -> None:  # M7
    findings = [_finding("tool.poisoning"), _finding("tool.invisible_unicode")]
    assert _state("C1", ["tool.poisoning", "tool.invisible_unicode"], findings, ALL_TYPES) == "fail"


def test_control_state_fail_takes_precedence_over_pass() -> None:  # M7
    # A present finding drives fail even if evaluated_types would otherwise pass.
    assert _state("C1", ["tool.poisoning"], [_finding("tool.poisoning")], set()) == "fail"


# ===========================================================================
# Group D — Result record structure (M10-M11).
# ===========================================================================
def _eval_one(cid: str, types: list[str], findings: list[Finding],
              evaluated: set[str]) -> ControlResult:
    pack = _one_control_pack(cid, types)
    return evaluate_pack(pack, findings, evaluated_types=evaluated).results[0]


def test_result_contains_control_id() -> None:  # M10
    assert _eval_one("C1", ["tool.poisoning"], [], ALL_TYPES).id == "C1"


def test_result_contains_control_title() -> None:  # M10
    assert _eval_one("C1", ["tool.poisoning"], [], ALL_TYPES).title == "C1 title"


def test_result_contains_state() -> None:  # M10
    assert _eval_one("C1", ["tool.poisoning"], [], ALL_TYPES).state in (
        "pass", "fail", "not_applicable")


def test_result_breaching_types_present_on_fail() -> None:  # M10
    r = _eval_one("C1", ["tool.poisoning"], [_finding("tool.poisoning")], ALL_TYPES)
    assert r.breaching_types == ("tool.poisoning",)


def test_result_breaching_types_empty_on_pass() -> None:  # M10
    assert _eval_one("C1", ["tool.poisoning"], [], ALL_TYPES).breaching_types == ()


def test_result_breaching_types_empty_on_not_applicable() -> None:  # M10
    assert _eval_one("C1", ["tool.poisoning"], [], set()).breaching_types == ()


def test_result_breaching_types_sorted() -> None:  # M10
    types = ["tool.poisoning", "tool.invisible_unicode", "tool.exfiltration"]
    findings = [_finding(t) for t in types]
    r = _eval_one("C1", types, findings, ALL_TYPES)
    assert r.breaching_types == tuple(sorted(types))


def test_evaluation_result_contains_pack_ref() -> None:  # M11
    pack = _one_control_pack("C1", ["tool.poisoning"])
    result = evaluate_pack(pack, [], evaluated_types=ALL_TYPES)
    assert result.pack_ref == PackRef("test", 1)


def test_evaluation_result_results_in_pack_order() -> None:  # M10
    pack = load_pack(_pack_yaml([("A", ["tool.poisoning"]), ("B", ["tool.exfiltration"]),
                                 ("C", ["tool.over_privilege"])]))
    result = evaluate_pack(pack, [], evaluated_types=ALL_TYPES)
    assert [r.id for r in result.results] == ["A", "B", "C"]


# ===========================================================================
# Group E — Full evaluation integration (M7-M12).
# ===========================================================================
def test_evaluate_pack_all_findings_match_all_controls() -> None:  # mixed states
    pack = load_pack(_pack_yaml([
        ("FAIL", ["tool.poisoning"]),          # finding present -> fail
        ("PASS", ["tool.exfiltration"]),       # evaluated, none present -> pass
        ("NA", ["tool.over_privilege"]),       # not evaluated -> not_applicable
    ]))
    result = evaluate_pack(
        pack, [_finding("tool.poisoning")],
        evaluated_types={"tool.poisoning", "tool.exfiltration"},
    )
    assert {r.id: r.state for r in result.results} == {
        "FAIL": "fail", "PASS": "pass", "NA": "not_applicable"}


def test_evaluate_pack_no_findings_all_types_evaluated_all_pass() -> None:  # M8
    result = evaluate_pack(load_baseline(), [], evaluated_types=ALL_TYPES)
    assert all(r.state == "pass" for r in result.results)


def test_evaluate_pack_no_findings_no_types_evaluated_all_not_applicable() -> None:  # M9
    result = evaluate_pack(load_baseline(), [], evaluated_types=set())
    assert all(r.state == "not_applicable" for r in result.results)


def test_evaluate_pack_many_to_many_mapping_m5() -> None:  # M5
    # One finding_type listed under two controls fails both.
    pack = load_pack(_pack_yaml([("A", ["tool.poisoning"]), ("B", ["tool.poisoning"])]))
    result = evaluate_pack(pack, [_finding("tool.poisoning")], evaluated_types=ALL_TYPES)
    assert all(r.state == "fail" for r in result.results)


def test_evaluate_pack_only_evaluated_types_affect_state() -> None:  # M8/M9
    # Two breached_by types; only one evaluated, none present -> still pass (M8).
    assert _state("C1", ["tool.poisoning", "tool.exfiltration"], [],
                  {"tool.exfiltration"}) == "pass"


# ===========================================================================
# Group F — Determinism (M12).
# ===========================================================================
def test_evaluate_pack_determinism_identical_twice() -> None:  # M12
    pack = load_baseline()
    findings = [_finding("tool.poisoning"), _finding("tool.exfiltration")]
    first = evaluate_pack(pack, findings, evaluated_types=ALL_TYPES)
    second = evaluate_pack(pack, findings, evaluated_types=ALL_TYPES)
    assert first == second
    assert isinstance(first, EvaluationResult)


def test_evaluate_pack_determinism_independent_of_finding_order() -> None:  # M12
    pack = _one_control_pack("C1", ["tool.poisoning", "tool.invisible_unicode",
                                    "tool.exfiltration"])
    types = ["tool.poisoning", "tool.invisible_unicode", "tool.exfiltration"]
    forward = evaluate_pack(pack, [_finding(t) for t in types], evaluated_types=ALL_TYPES)
    reverse = evaluate_pack(pack, [_finding(t) for t in reversed(types)],
                            evaluated_types=ALL_TYPES)
    assert forward == reverse
