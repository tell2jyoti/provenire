"""Request/response schemas for the scan API (scan-api-spec §3, A1-A11).

Pydantic models pin the wire shape. The request is validated leniently here and
policed for status codes in the handler (transport/mode drive 400 vs 402, not a
blanket 422); the response models are the single source of truth for the 200 and
error bodies. control_plane may import attestable_engine, never cli — and no
regulation is named (architecture law).
"""

from __future__ import annotations

from pydantic import BaseModel


class ScanRequest(BaseModel):
    """POST /scan body (A1-A5). Defaults per spec; policed in the handler."""

    target: str = ""
    transport: str = "streamable_http"
    mode: str = "deterministic"


class Summary(BaseModel):
    """Per-severity survivor counts + the pass/fail gate (A7)."""

    critical: int
    high: int
    medium: int
    low: int
    gate: str


class FindingModel(BaseModel):
    """One survivor, framework-neutral (A8). `type` is the engine finding_type."""

    id: str
    type: str
    severity: str
    confidence: float
    entity: str
    rationale: str


class ScanResponse(BaseModel):
    """200 body (A6-A11). `report_url` is null until the persistence slice lands."""

    scan_id: str
    server_hash: str
    summary: Summary
    findings: list[FindingModel]
    report_url: str | None = None


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    """Every mapped error renders as `{"error": {"code", "message"}}` (E1-E6)."""

    error: ErrorBody


__all__ = [
    "ScanRequest",
    "Summary",
    "FindingModel",
    "ScanResponse",
    "ErrorBody",
    "ErrorResponse",
]
