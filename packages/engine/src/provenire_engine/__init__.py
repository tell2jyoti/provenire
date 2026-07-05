"""Provenire engine — framework-neutral MCP detection (open core)."""

from __future__ import annotations

from .connect.errors import TargetUnreachable
from .connect.session import Transport
from .detect import detect_over_privilege, detect_poisoning
from .enumerate.manifest import Manifest, PromptRecord, ResourceRecord, ToolRecord
from .finding import Finding
from .report import Report, build_report
from .scan import scan
from .score import ScanResult, ScanScore, score_findings

__all__ = [
    "scan",
    "Manifest",
    "ToolRecord",
    "ResourceRecord",
    "PromptRecord",
    "Finding",
    "detect_poisoning",
    "detect_over_privilege",
    "score_findings",
    "ScanResult",
    "ScanScore",
    "build_report",
    "Report",
    "TargetUnreachable",
    "Transport",
]
