"""§5 — report (feature F5). Rules RP0–RP4.

`build_report(manifest, result)` renders a scored scan into two artifacts: a
machine-readable JSON string and a human-readable, self-contained HTML document.
Both are pure/deterministic functions of the input (no clock/scan_id/duration),
and the HTML escapes hostile finding text (XSS). Findings/manifests are built
directly — no network, no SDK.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import pytest

from attestable_engine import Finding, build_report, score_findings
from attestable_engine.enumerate.manifest import Manifest, ToolRecord, build_manifest
from attestable_engine.report import Report


def _manifest(*tools: ToolRecord, transport: str = "stdio") -> Manifest:
    return build_manifest(list(tools), [], [], transport=transport)  # type: ignore[arg-type]


def _f(
    finding_type: str = "tool.poisoning",
    entity_ref: str = "tool:x",
    severity: str = "high",
    confidence: float = 0.9,
    rationale: str = "why",
) -> Finding:
    return Finding(finding_type, entity_ref, severity, confidence, rationale)  # type: ignore[arg-type]


def _report(
    findings: Iterable[Finding] = (),
    *,
    tools: Iterable[ToolRecord] = (),
    transport: str = "stdio",
    schema_version: str = "1.0",
) -> Report:
    manifest = _manifest(*tools, transport=transport)
    result = score_findings(list(findings), confidence_floor=0.0)
    return build_report(manifest, result, schema_version=schema_version)


def _json(report: Report) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(report.json)
    return data


# --------------------------------------------------------------------------- RP0
def test_rp0_empty_result_json_has_empty_findings_array() -> None:
    data = _json(_report([]))
    assert data["findings"] == []
    assert data["summary"] == {
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "worst": None,
        "gate": "pass",
    }


def test_rp0_empty_result_html_is_valid_document() -> None:
    html = _report([]).html
    assert html.strip().lower().startswith("<!doctype html")
    assert "</html>" in html
    assert "no findings" in html.lower()


# --------------------------------------------------------------------------- RP1
def test_rp1_json_parses_as_valid_json() -> None:
    assert isinstance(_json(_report([_f()])), dict)


def test_rp1_json_top_level_keys_exact() -> None:
    assert set(_json(_report([_f()]))) == {
        "schema_version",
        "manifest_hash",
        "transport",
        "summary",
        "findings",
    }


def test_rp1_json_schema_version_default_and_override() -> None:
    assert _json(_report([_f()]))["schema_version"] == "1.0"
    assert _json(_report([_f()], schema_version="2.0"))["schema_version"] == "2.0"


def test_rp1_json_manifest_hash_matches() -> None:
    manifest = _manifest(ToolRecord("t"))
    result = score_findings([], confidence_floor=0.0)
    data = json.loads(build_report(manifest, result).json)
    assert data["manifest_hash"] == manifest.manifest_hash


def test_rp1_json_transport_matches() -> None:
    assert _json(_report([_f()], transport="streamable_http"))["transport"] == "streamable_http"


def test_rp1_json_summary_keys_exact() -> None:
    assert set(_json(_report([_f()]))["summary"]) == {"counts", "worst", "gate"}


def test_rp1_json_summary_counts_all_four_keys() -> None:
    counts = _json(_report([_f()]))["summary"]["counts"]
    assert set(counts) == {"critical", "high", "medium", "low"}
    assert all(isinstance(v, int) for v in counts.values())


def test_rp1_json_summary_counts_values_correct() -> None:
    findings = [
        _f(severity="critical", entity_ref="tool:a"),
        _f(severity="critical", entity_ref="tool:b"),
        _f(severity="high", entity_ref="tool:c"),
        _f(severity="low", entity_ref="tool:d"),
    ]
    assert _json(_report(findings))["summary"]["counts"] == {
        "critical": 2,
        "high": 1,
        "medium": 0,
        "low": 1,
    }


@pytest.mark.parametrize(
    ("severity", "expected"), [("critical", "critical"), ("low", "low")]
)
def test_rp1_json_summary_worst_matches(severity: str, expected: str) -> None:
    assert _json(_report([_f(severity=severity)]))["summary"]["worst"] == expected


def test_rp1_json_summary_worst_null_when_empty() -> None:
    assert _json(_report([]))["summary"]["worst"] is None


@pytest.mark.parametrize(
    ("severity", "gate"), [("high", "fail"), ("low", "pass")]
)
def test_rp1_json_summary_gate(severity: str, gate: str) -> None:
    # default gate_threshold "high": high fails, low passes.
    assert _json(_report([_f(severity=severity)]))["summary"]["gate"] == gate


def test_rp1_json_findings_array_length() -> None:
    findings = [_f(entity_ref=f"tool:{i}") for i in range(3)]
    assert len(_json(_report(findings))["findings"]) == 3


def test_rp1_json_findings_in_result_order() -> None:
    # F4 risk order: critical > high > low.
    findings = [
        _f(severity="low", entity_ref="tool:c"),
        _f(severity="critical", entity_ref="tool:a"),
        _f(severity="high", entity_ref="tool:b"),
    ]
    refs = [f["entity_ref"] for f in _json(_report(findings))["findings"]]
    assert refs == ["tool:a", "tool:b", "tool:c"]


def test_rp1_json_finding_keys_exact() -> None:
    finding = _json(_report([_f()]))["findings"][0]
    assert set(finding) == {"finding_type", "entity_ref", "severity", "confidence", "rationale"}


def test_rp1_json_finding_fields_map_correctly() -> None:
    f = _f(
        finding_type="tool.exfiltration",
        entity_ref="tool:send_email",
        severity="critical",
        confidence=0.8,
        rationale="exfiltration: egress 'send'",
    )
    got = _json(_report([f]))["findings"][0]
    assert got == {
        "finding_type": "tool.exfiltration",
        "entity_ref": "tool:send_email",
        "severity": "critical",
        "confidence": 0.8,
        "rationale": "exfiltration: egress 'send'",
    }


def test_rp1_json_confidence_is_number_not_string() -> None:
    conf = _json(_report([_f(confidence=0.85)]))["findings"][0]["confidence"]
    assert isinstance(conf, float)
    assert conf == 0.85


# --------------------------------------------------------------------------- RP2
def test_rp2_same_inputs_same_json_bytes() -> None:
    manifest = _manifest(ToolRecord("t"))
    result = score_findings([_f()], confidence_floor=0.0)
    assert build_report(manifest, result).json == build_report(manifest, result).json


def test_rp2_same_inputs_same_html_bytes() -> None:
    manifest = _manifest(ToolRecord("t"))
    result = score_findings([_f()], confidence_floor=0.0)
    assert build_report(manifest, result).html == build_report(manifest, result).html


def test_rp2_different_result_different_json() -> None:
    manifest = _manifest(ToolRecord("t"))
    r1 = score_findings([_f(entity_ref="tool:a")], confidence_floor=0.0)
    r2 = score_findings(
        [_f(entity_ref="tool:a"), _f(entity_ref="tool:b")], confidence_floor=0.0
    )
    assert build_report(manifest, r1).json != build_report(manifest, r2).json


def test_rp2_different_manifest_different_json() -> None:
    result = score_findings([_f()], confidence_floor=0.0)
    j1 = build_report(_manifest(ToolRecord("A")), result).json
    j2 = build_report(_manifest(ToolRecord("B")), result).json
    assert j1 != j2


def test_rp2_no_volatile_metadata_keys_in_json() -> None:
    # Structural absence — the engine artifact carries no run metadata (injected
    # by F6/F7). Not a substring scan: a rationale like "id_rsa" contains "id".
    data = _json(_report([_f(rationale="exfiltration with id_rsa")]))
    for volatile in ("scan_id", "timestamp", "created_at", "duration", "duration_ms", "id"):
        assert volatile not in data
        assert volatile not in data["findings"][0]


# --------------------------------------------------------------------------- RP3
def test_rp3_html_starts_with_doctype() -> None:
    assert _report([_f()]).html.strip().lower().startswith("<!doctype html")


def test_rp3_html_is_complete_document() -> None:
    html = _report([_f()]).html.lower()
    for tag in ("<html", "<head", "<body", "</body>", "</html>"):
        assert tag in html


def test_rp3_html_chrome_has_no_external_refs() -> None:
    # Benign findings (no URLs in text) → the report's own markup must reference
    # nothing external and run no script (offline, no proprietary viewer).
    html = _report([_f(rationale="benign description")]).html.lower()
    for token in ("<script", "<link", "<iframe", " src=", " href=", "url(", "//"):
        assert token not in html


def test_rp3_html_contains_summary_and_table() -> None:
    html = _report([_f(severity="high")]).html.lower()
    assert "<table" in html
    for header in ("finding_type", "entity_ref", "severity", "confidence", "rationale"):
        assert header in html
    assert "gate" in html


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        'quote" and \'apos',
        "amp & amp",
        "less < greater >",
    ],
)
def test_rp3_xss_hostile_text_is_escaped(payload: str) -> None:
    # A hostile MCP server plants markup in a finding field; it must render as
    # inert, escaped text — never live markup or a broken attribute.
    html = _report([_f(entity_ref=payload, rationale=payload)]).html
    assert "<script>" not in html  # raw tag never survives
    assert payload not in html  # the raw special chars are transformed
    # The escaped forms are present instead.
    if "<" in payload:
        assert "&lt;" in html
    if '"' in payload:
        assert "&quot;" in html
    if "'" in payload:
        assert "&#x27;" in html
    if "&" in payload:
        assert "&amp;" in html


def test_rp3_attacker_url_in_rationale_is_inert_text() -> None:
    # A P3 exfil rationale legitimately contains an external URL. It must appear
    # as escaped text, NOT as a live href/src the browser would fetch.
    html = _report(
        [_f(rationale="exfiltration: egress 'send' with https://evil.example/steal")]
    ).html
    assert "evil.example" in html  # shown to the human (as text)
    assert 'href="https://evil.example' not in html
    assert 'src="https://evil.example' not in html
    assert "<script" not in html.lower()


# --------------------------------------------------------------------------- RP4
def test_rp4_every_finding_appears_once_in_both_artifacts() -> None:
    findings = [_f(entity_ref=f"tool:{c}", severity="high") for c in ("a", "b", "d")]
    report = _report(findings)
    data = _json(report)
    assert [f["entity_ref"] for f in data["findings"]] == ["tool:a", "tool:b", "tool:d"]
    for ref in ("tool:a", "tool:b", "tool:d"):
        assert report.html.count(ref) == 1


def test_rp4_no_phantom_or_duplicate_findings() -> None:
    findings = [_f(entity_ref="tool:a"), _f(entity_ref="tool:b", severity="low")]
    assert len(_json(_report(findings))["findings"]) == 2


def test_rp4_summary_matches_result_score() -> None:
    findings = [
        _f(severity="critical", entity_ref="tool:a"),
        _f(severity="high", entity_ref="tool:b"),
        _f(severity="high", entity_ref="tool:c"),
    ]
    manifest = _manifest(ToolRecord("t"))
    result = score_findings(findings, confidence_floor=0.0)
    data = json.loads(build_report(manifest, result).json)
    assert data["summary"]["counts"] == result.score.counts
    assert data["summary"]["worst"] == result.score.worst
    assert data["summary"]["gate"] == result.score.gate


def test_rp4_html_summary_renders_result_score_values() -> None:
    # RP4: the numbers a human reads in the HTML must equal result.score — not
    # just "a summary exists". A mutation swapping counts would fail here.
    findings = [
        _f(severity="critical", entity_ref="tool:a"),
        _f(severity="high", entity_ref="tool:b"),
    ]
    html = _report(findings).html.lower()
    assert 'class="gate-fail">fail</strong>' in html  # critical >= high threshold
    assert "worst severity: critical" in html
    assert "critical: 1" in html
    assert "high: 1" in html
    assert "medium: 0" in html
    assert "low: 0" in html


def test_rp4_html_summary_empty_renders_pass_and_none() -> None:
    html = _report([]).html.lower()
    assert 'class="gate-pass">pass</strong>' in html
    assert "worst severity: none" in html
    assert "critical: 0" in html


def test_rp4_findings_order_matches_result_order() -> None:
    findings = [
        _f(severity="low", entity_ref="tool:c", confidence=0.6),
        _f(severity="high", entity_ref="tool:b", confidence=0.7),
        _f(severity="critical", entity_ref="tool:a", confidence=0.9),
    ]
    manifest = _manifest(ToolRecord("t"))
    result = score_findings(findings, confidence_floor=0.0)
    expected = [f.entity_ref for f in result.findings]
    got = [f["entity_ref"] for f in json.loads(build_report(manifest, result).json)["findings"]]
    assert got == expected


def test_report_is_frozen() -> None:
    import dataclasses

    report = _report([_f()])
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.json = "{}"  # type: ignore[misc]
