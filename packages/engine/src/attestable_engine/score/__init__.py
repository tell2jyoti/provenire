"""Scoring (§4, feature F4) — normalize provisional findings into a ScanResult."""

from __future__ import annotations

from .scoring import ScanResult, ScanScore, score_findings

__all__ = ["ScanResult", "ScanScore", "score_findings"]
