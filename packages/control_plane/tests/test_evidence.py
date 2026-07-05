"""evidence-export-spec — F9 evidence export (control_plane, COMMERCIAL).

Rules EV1-EV13. The evidence document is the pack-driven, deterministic compliance
record: which pack (id+version) judged which controls over which findings. The
builder is a **pure** function of its inputs + injected provenance — no clock, no
RNG, no I/O (EV10/EV11). Finding text is recorded verbatim (JSON-escaped), never
stripped (EV13) — evidence must be faithful. control_plane imports provenire_engine
+ the F8 mapping layer (allowed); nothing here imports cli; no regulation is named.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from typing import Any

import pytest
from provenire_engine import Finding, ScanResult, score_findings
from provenire_engine.enumerate.manifest import Manifest, build_manifest

from provenire_control_plane.evidence.bundle import Evidence, build_evidence
from provenire_control_plane.mapping.evaluate import EvaluationResult, evaluate_pack
from provenire_control_plane.mapping.pack import load_baseline

ALL_TYPES = {
    "tool.poisoning",
    "tool.invisible_unicode",
    "tool.exfiltration",
    "tool.over_privilege",
    "tool.missing_schema",
    "tool.unbounded_schema",
}

_AT = "2026-07-04T12:00:00Z"
_SID = "scn_deadbeef"


# --- helpers ---------------------------------------------------------------
def _manifest(transport: str = "streamable_http") -> Manifest:
    return build_manifest([], [], [], transport=transport)  # type: ignore[arg-type]


def _finding(finding_type: str, *, entity: str = "tool:x", severity: str = "high",
             confidence: float = 0.9, rationale: str = "because") -> Finding:
    return Finding(finding_type, entity, severity, confidence, rationale)  # type: ignore[arg-type]


def _result(findings: list[Finding]) -> ScanResult:
    return score_findings(findings)


def _evaluation(findings: list[Finding], *, evaluated: set[str] | None = None) -> EvaluationResult:
    eval_set = evaluated if evaluated is not None else set(ALL_TYPES)
    return evaluate_pack(load_baseline(), findings, evaluated_types=eval_set)


def _build(findings: list[Finding] | None = None, *, evaluated: set[str] | None = None,
           transport: str = "streamable_http", generated_at: str = _AT,
           scan_id: str = _SID, schema_version: str = "1.0") -> Evidence:
    findings = findings if findings is not None else []
    ev_types = evaluated if evaluated is not None else set(ALL_TYPES)
    return build_evidence(
        _manifest(transport), _result(findings),
        _evaluation(findings, evaluated=ev_types),
        generated_at=generated_at, scan_id=scan_id, schema_version=schema_version,
    )


def _doc(**kw: Any) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(_build(**kw).json)
    return result


# ===========================================================================
# Group A — Builder signature & Evidence value (EV7-EV9).
# ===========================================================================
def test_evidence_is_frozen_dataclass() -> None:  # EV9
    ev = _build()
    assert dataclasses.is_dataclass(ev)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.json = "mutated"  # type: ignore[misc]


def test_evidence_exposes_json_string() -> None:  # EV9
    assert isinstance(_build().json, str)


def test_build_evidence_returns_evidence_instance() -> None:  # EV9
    assert isinstance(_build(), Evidence)


def test_signature_structured_inputs_positional() -> None:  # EV8
    params = inspect.signature(build_evidence).parameters
    for name in ("manifest", "result", "evaluation"):
        assert params[name].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


def test_signature_provenance_keyword_only() -> None:  # EV8
    params = inspect.signature(build_evidence).parameters
    for name in ("generated_at", "scan_id", "schema_version"):
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY


def test_schema_version_defaults_to_1_0() -> None:  # EV7/EV8
    assert _doc()["schema_version"] == "1.0"


# ===========================================================================
# Group B — Document shape (EV1, EV7).
# ===========================================================================
def test_json_parses_as_dict() -> None:  # EV1
    assert isinstance(json.loads(_build().json), dict)


def test_top_level_keys_exact_set() -> None:  # EV1
    assert set(_doc()) == {
        "schema_version", "generated_at", "scan_id", "pack", "server",
        "summary", "controls", "findings",
    }


def test_schema_version_override_respected() -> None:  # EV7
    assert _doc(schema_version="2.3")["schema_version"] == "2.3"


# ===========================================================================
# Group C — Pack section (EV2).
# ===========================================================================
def test_pack_section_has_id_and_version() -> None:  # EV2
    assert set(_doc()["pack"]) == {"id", "version"}


def test_pack_id_from_pack_ref() -> None:  # EV2
    assert _doc()["pack"]["id"] == "baseline"


def test_pack_version_from_pack_ref() -> None:  # EV2
    assert _doc()["pack"]["version"] == 1


# ===========================================================================
# Group D — Server section (EV3).
# ===========================================================================
def test_server_section_keys() -> None:  # EV3
    assert set(_doc()["server"]) == {"manifest_hash", "transport"}


def test_server_hash_from_manifest() -> None:  # EV3
    assert _doc()["server"]["manifest_hash"] == _manifest().manifest_hash


def test_server_transport_from_manifest() -> None:  # EV3
    assert _doc(transport="stdio")["server"]["transport"] == "stdio"


# ===========================================================================
# Group E — Summary section (EV4).
# ===========================================================================
def test_summary_counts_all_four_severities() -> None:  # EV4
    assert set(_doc()["summary"]["counts"]) == {"critical", "high", "medium", "low"}


def test_summary_counts_values_match_score() -> None:  # EV4
    findings = [_finding("tool.exfiltration", severity="critical")]
    doc = _doc(findings=findings)
    counts = _result(findings).score.counts
    assert doc["summary"]["counts"] == {k: counts[k] for k in counts}


def test_summary_worst_matches_score() -> None:  # EV4
    doc = _doc(findings=[_finding("tool.exfiltration", severity="critical")])
    assert doc["summary"]["worst"] == "critical"


def test_summary_worst_null_when_no_findings() -> None:  # EV4
    assert _doc()["summary"]["worst"] is None


def test_summary_gate_matches_score() -> None:  # EV4
    doc = _doc(findings=[_finding("tool.exfiltration", severity="critical")])
    assert doc["summary"]["gate"] == "fail"


# ===========================================================================
# Group F — Controls section (EV5).
# ===========================================================================
def test_controls_is_list() -> None:  # EV5
    assert isinstance(_doc()["controls"], list)


def test_controls_in_evaluation_order() -> None:  # EV5
    doc_ids = [c["id"] for c in _doc()["controls"]]
    eval_ids = [r.id for r in _evaluation([]).results]
    assert doc_ids == eval_ids


def test_control_entry_fields() -> None:  # EV5
    for c in _doc()["controls"]:
        assert set(c) == {"id", "title", "state", "breaching_types"}


def test_control_state_valid_values() -> None:  # EV5
    for c in _doc()["controls"]:
        assert c["state"] in ("pass", "fail", "not_applicable")


def test_control_breaching_empty_unless_fail() -> None:  # EV5
    for c in _doc(findings=[_finding("tool.exfiltration", severity="critical")])["controls"]:
        if c["state"] != "fail":
            assert c["breaching_types"] == []


def test_control_breaching_types_sorted() -> None:  # EV5
    findings = [_finding("tool.poisoning"), _finding("tool.invisible_unicode")]
    doc = _doc(findings=findings)
    injection = next(c for c in doc["controls"] if c["id"] == "MCP-INJECTION")
    assert injection["state"] == "fail"
    assert injection["breaching_types"] == sorted(injection["breaching_types"])
    assert injection["breaching_types"] == ["tool.invisible_unicode", "tool.poisoning"]


# ===========================================================================
# Group G — Findings section (EV6).
# ===========================================================================
def test_findings_is_list() -> None:  # EV6
    assert isinstance(_doc()["findings"], list)


def test_findings_in_scan_result_order() -> None:  # EV6
    findings = [_finding("tool.exfiltration", severity="critical"),
                _finding("tool.poisoning")]
    doc = _doc(findings=findings)
    result_order = [f.entity_ref for f in _result(findings).findings]
    assert [f["entity_ref"] for f in doc["findings"]] == result_order


def test_finding_entry_fields() -> None:  # EV6
    doc = _doc(findings=[_finding("tool.exfiltration", severity="critical")])
    assert set(doc["findings"][0]) == {
        "finding_type", "entity_ref", "severity", "confidence", "rationale"}


def test_finding_values_match_input() -> None:  # EV6
    findings = [_finding("tool.exfiltration", entity="tool:pay", severity="critical",
                         confidence=0.8, rationale="egress to evil")]
    f = _doc(findings=findings)["findings"][0]
    assert f["finding_type"] == "tool.exfiltration"
    assert f["entity_ref"] == "tool:pay"
    assert f["severity"] == "critical"
    assert f["confidence"] == 0.8
    assert f["rationale"] == "egress to evil"


# ===========================================================================
# Group H — Determinism & provenance (EV10, EV11).
# ===========================================================================
def test_identical_inputs_identical_json() -> None:  # EV10
    findings = [_finding("tool.exfiltration", severity="critical")]
    first = _build(findings=findings)
    second = _build(findings=findings)
    assert first.json == second.json


def test_generated_at_verbatim() -> None:  # EV11
    assert _doc(generated_at="2030-01-02T03:04:05Z")["generated_at"] == "2030-01-02T03:04:05Z"


def test_scan_id_verbatim() -> None:  # EV11
    assert _doc(scan_id="scn_abc123")["scan_id"] == "scn_abc123"


# ===========================================================================
# Group I — Serialization & faithful text (EV12, EV13).
# ===========================================================================
def test_json_keys_sorted_and_compact() -> None:  # EV12
    raw = _build(findings=[_finding("tool.exfiltration", severity="critical")]).json
    # Re-serializing the parsed doc with sorted keys + compact separators must be
    # byte-identical — proves the builder sorted keys and used compact separators.
    assert raw == json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"))


def test_no_incidental_whitespace() -> None:  # EV12
    assert ", " not in _build().json and '": ' not in _build().json


def test_control_bytes_in_rationale_preserved() -> None:  # EV13
    findings = [_finding("tool.exfiltration", severity="critical", rationale="bad\x00\x1btext")]
    doc = _doc(findings=findings)
    assert doc["findings"][0]["rationale"] == "bad\x00\x1btext"


# ===========================================================================
# Group J — Full-build fixtures (EV2-EV13).
# ===========================================================================
def test_full_build_mixed_states() -> None:  # EV2-EV6
    findings = [_finding("tool.exfiltration", severity="critical")]
    # Evaluate everything except the schema types → MCP-SCHEMA is not_applicable.
    evaluated = ALL_TYPES - {"tool.missing_schema", "tool.unbounded_schema"}
    doc = _doc(findings=findings, evaluated=evaluated)
    states = {c["id"]: c["state"] for c in doc["controls"]}
    assert states == {
        "MCP-INJECTION": "pass",
        "MCP-EXFIL": "fail",
        "MCP-LEASTPRIV": "pass",
        "MCP-SCHEMA": "not_applicable",
    }
    assert doc["pack"] == {"id": "baseline", "version": 1}
    assert len(doc["findings"]) == 1


def test_clean_scan_all_pass() -> None:  # EV4/EV5/EV6
    doc = _doc()  # no findings, all types evaluated
    assert all(c["state"] == "pass" for c in doc["controls"])
    assert doc["findings"] == []
    assert doc["summary"]["gate"] == "pass"
    assert doc["summary"]["worst"] is None


def test_determinism_byte_identical() -> None:  # EV10/EV12
    findings = [_finding("tool.poisoning"), _finding("tool.exfiltration", severity="critical")]
    a = _build(findings=findings)
    b = _build(findings=findings)
    assert a.json == b.json
