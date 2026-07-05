"""Report rendering (§5, feature F5, layer: engine).

Deterministic, no-LLM rendering of a scored scan into two artifacts: a
machine-readable JSON string and a human-readable, self-contained HTML document.

- **Pure & deterministic (RP2):** ``build_report`` is a function of
  ``(manifest, result, schema_version)`` only — no clock, no ``scan_id``, no
  ``duration``. Run metadata is injected by the CLI (F6) / hosted API (F7) around
  this core (TDD §10), so the same scan renders byte-identical every time.
- **Untrusted content (RP3):** every finding/manifest text field originates from
  a hostile MCP server, so the HTML escapes all interpolated values
  (``html.escape(..., quote=True)``) — the report is a prime XSS sink. The HTML is
  fully self-contained (inlined CSS, no external URL/CDN/script) so it is
  readable offline with no proprietary viewer (NFR-07).

The engine **returns** the artifact strings; persistence to
``reports/{scan_id}.{json,html}`` is the caller's job. It names no regulation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from html import escape
from typing import Any

from ..enumerate.manifest import Manifest
from ..finding import Finding, Severity
from ..score import ScanResult

_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class Report:
    """The two rendered artifacts. Immutable strings."""

    json: str
    html: str


def build_report(
    manifest: Manifest,
    result: ScanResult,
    *,
    schema_version: str = "1.0",
) -> Report:
    """Render ``result`` into a :class:`Report` per spec §5 (RP0–RP4)."""
    payload = _payload(manifest, result, schema_version)
    # Canonical, deterministic serialization (mirrors manifest `_canon`): sorted
    # keys + fixed separators + ensure_ascii, so the bytes never drift.
    json_str = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return Report(json=json_str, html=_render_html(payload))


def _payload(manifest: Manifest, result: ScanResult, schema_version: str) -> dict[str, Any]:
    # The RP1 shape. Findings stay in ScanResult order (F4 risk order) — no
    # re-sorting here (RP4).
    return {
        "schema_version": schema_version,
        "manifest_hash": manifest.manifest_hash,
        "transport": manifest.transport,
        "summary": {
            "counts": {sev: result.score.counts[sev] for sev in _SEVERITIES},
            "worst": result.score.worst,
            "gate": result.score.gate,
        },
        "findings": [_finding_dict(f) for f in result.findings],
    }


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "finding_type": f.finding_type,
        "entity_ref": f.entity_ref,
        "severity": f.severity,
        "confidence": f.confidence,
        "rationale": f.rationale,
    }


# --- HTML rendering (self-contained; every interpolated value is escaped) -----

_CSS = (
    "body{font-family:system-ui,sans-serif;margin:2rem;color:#111}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}"
    "th{background:#f0f0f0}"
    ".gate-fail{color:#b00}.gate-pass{color:#070}"
)


def _e(value: object) -> str:
    """Escape any interpolated value for safe HTML text/attribute context."""
    return escape(str(value), quote=True)


def _render_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    counts = summary["counts"]
    gate = summary["gate"]
    counts_line = ", ".join(f"{sev}: {_e(counts[sev])}" for sev in _SEVERITIES)
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Provenire scan report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Provenire scan report</h1>",
        "<section>",
        f'<p>Gate: <strong class="gate-{_e(gate)}">{_e(gate)}</strong></p>',
        f"<p>Worst severity: {_e(summary['worst'] if summary['worst'] else 'none')}</p>",
        f"<p>Counts &mdash; {counts_line}</p>",
        f"<p>Manifest: {_e(payload['manifest_hash'])} "
        f"(transport {_e(payload['transport'])})</p>",
        "</section>",
        _findings_html(payload["findings"]),
        "</body></html>",
    ]
    return "".join(parts)


def _findings_html(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p>No findings.</p>"
    header = (
        "<thead><tr><th>finding_type</th><th>entity_ref</th><th>severity</th>"
        "<th>confidence</th><th>rationale</th></tr></thead>"
    )
    rows = "".join(
        "<tr>"
        f"<td>{_e(f['finding_type'])}</td>"
        f"<td>{_e(f['entity_ref'])}</td>"
        f"<td>{_e(f['severity'])}</td>"
        f"<td>{_e(f['confidence'])}</td>"
        f"<td>{_e(f['rationale'])}</td>"
        "</tr>"
        for f in findings
    )
    return f"<table>{header}<tbody>{rows}</tbody></table>"


__all__ = ["Report", "build_report"]
