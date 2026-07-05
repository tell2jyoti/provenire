"""Normalize raw session primitives (R6).

Defaults absent/None optionals; coerces present-but-wrong-typed values instead
of dropping them (so R5c stays sensitive and a hostile server cannot crash the
scan). `input_schema` falls back to `{}` when it is not a JSON object — a
non-`dict`, or a `dict` that is not JSON-clean (non-string keys, non-serializable
values, cycles).
"""

from __future__ import annotations

import json
from typing import Any

from .manifest import PromptRecord, ResourceRecord, ToolRecord


def _str(value: Any) -> str:
    # Absent/None → ""; anything else coerced, preserving the information rather
    # than silently zeroing a present field. Coercion is total: a hostile object
    # whose __str__ itself raises still cannot crash the scan (R6).
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _schema(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    try:
        json.dumps(value, sort_keys=True)  # reject non-string keys / non-JSON
    except (TypeError, ValueError, RecursionError):
        return {}
    return value


def to_tool_record(obj: Any) -> ToolRecord:
    return ToolRecord(
        name=_str(getattr(obj, "name", None)),
        description=_str(getattr(obj, "description", None)),
        input_schema=_schema(getattr(obj, "input_schema", None)),
    )


def to_resource_record(obj: Any) -> ResourceRecord:
    return ResourceRecord(
        uri=_str(getattr(obj, "uri", None)),
        name=_str(getattr(obj, "name", None)),
        description=_str(getattr(obj, "description", None)),
    )


def to_prompt_record(obj: Any) -> PromptRecord:
    return PromptRecord(
        name=_str(getattr(obj, "name", None)),
        description=_str(getattr(obj, "description", None)),
    )
