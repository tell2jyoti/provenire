"""Normalized manifest model + canonical hash (R5, §2.1)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ..connect.session import Transport


@dataclass(frozen=True)
class ToolRecord:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceRecord:
    uri: str
    name: str = ""
    description: str = ""


@dataclass(frozen=True)
class PromptRecord:
    name: str
    description: str = ""


@dataclass(frozen=True)
class Manifest:
    # Record sequences are immutable tuples; the contained input_schema dicts are
    # treated as read-only, so a built manifest stays consistent with its hash.
    tools: tuple[ToolRecord, ...]
    resources: tuple[ResourceRecord, ...]
    prompts: tuple[PromptRecord, ...]
    transport: Transport
    manifest_hash: str


def _tool_dict(t: ToolRecord) -> dict[str, Any]:
    return {"name": t.name, "description": t.description, "input_schema": t.input_schema}


def _resource_dict(r: ResourceRecord) -> dict[str, Any]:
    return {"uri": r.uri, "name": r.name, "description": r.description}


def _prompt_dict(p: PromptRecord) -> dict[str, Any]:
    return {"name": p.name, "description": p.description}


def _canon(value: Any) -> str:
    # Deterministic canonical JSON. `default=str` tolerates non-serializable
    # *values*; the fallback also covers non-string *keys* / cycles so the hash
    # layer never raises on hostile input, independent of normalization (R6).
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError, RecursionError):
        return json.dumps(repr(value), separators=(",", ":"))


def build_manifest(
    tools: Sequence[ToolRecord],
    resources: Sequence[ResourceRecord],
    prompts: Sequence[PromptRecord],
    *,
    transport: Transport,
) -> Manifest:
    """Sort by full canonical content, then hash.

    Sorting on the whole record (not just name/uri) gives a *total* order, so
    duplicate names/uris are deterministic and the hash is order-independent
    even for them (R5b).
    """
    sorted_tools = sorted(tools, key=lambda t: _canon(_tool_dict(t)))
    sorted_resources = sorted(resources, key=lambda r: _canon(_resource_dict(r)))
    sorted_prompts = sorted(prompts, key=lambda p: _canon(_prompt_dict(p)))
    canonical = {
        "tools": [_tool_dict(t) for t in sorted_tools],
        "resources": [_resource_dict(r) for r in sorted_resources],
        "prompts": [_prompt_dict(p) for p in sorted_prompts],
        # Transport is excluded: stdio vs streamable_http is the same server.
    }
    blob = _canon(canonical).encode("utf-8")
    manifest_hash = "sha256:" + hashlib.sha256(blob).hexdigest()
    return Manifest(
        tools=tuple(sorted_tools),
        resources=tuple(sorted_resources),
        prompts=tuple(sorted_prompts),
        transport=transport,
        manifest_hash=manifest_hash,
    )
