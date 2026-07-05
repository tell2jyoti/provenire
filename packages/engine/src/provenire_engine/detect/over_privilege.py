"""Over-privilege & schema-weakness detection (§3.3, feature F3, layer: engine).

Deterministic, no-LLM detection over a normalized ``Manifest``'s **tools** only
(capabilities and ``input_schema`` are tool concepts). Two threat classes:
over-privileged capabilities (shell / file-write / raw-sql / egress) inferred
from the tool's text + schema property names, and schema weaknesses (no
validation, or unbounded validation). Emits framework-neutral ``Finding``s
(§2.2) in canonical ``(entity_ref, finding_type)`` order, ≤1 per pair.
"""

from __future__ import annotations

import re

from ..enumerate.manifest import Manifest, ToolRecord
from ..finding import Finding


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# --- O1 capability seed sets (extensible; each new pattern needs a test, §3.3) ---
_CAPABILITIES: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "shell",
        _compile(
            r"\bshell\b",
            r"\bbash\b",
            r"/bin/sh",
            r"/bin/bash",
            r"\bsubprocess\b",
            r"os\.system",
            r"\bshell command\b",
            r"\bsystem command\b",
            r"\b(?:execute|run) (?:a |an |arbitrary )?command\b",
            r"\barbitrary code\b",
        ),
    ),
    (
        "file-write",
        _compile(
            r"\b(?:write|create|delete|remove|overwrite|rename|modify|append) "
            r"(?:a |the )?(?:file|directory|path)\b",
            r"\bchmod\b",
            r"\bmkdir\b",
            r"\brmdir\b",
            r"\bunlink\b",
            r"\bfilesystem write\b",
        ),
    ),
    (
        "raw-sql",
        _compile(
            r"\braw sql\b",
            r"\bsql query\b",
            r"\b(?:execute|run) (?:a |an |arbitrary )?query\b",
            r"\barbitrary query\b",
            r"\bdatabase query\b",
        )
        # SQL keywords matched CASE-SENSITIVELY: literal `SELECT`/`DROP`/… is raw
        # SQL, but lowercase "select a row"/"drop a note" is ordinary English and
        # would false-positive (code+qa review).
        + tuple(
            re.compile(p)
            for p in (r"\bSELECT\b", r"\bDROP\b", r"\bDELETE FROM\b", r"\bINSERT INTO\b")
        ),
    ),
    (
        "egress",
        _compile(
            r"\bhttps? request\b",
            r"\bmake (?:a |an )?request\b",
            r"\bfetch (?:a )?url\b",
            r"\boutbound\b",
            r"\bwebhook\b",
            r"\bnetwork request\b",
            r"\bapi call\b",
            r"\bcurl\b",
            r"\bexternal endpoint\b",
        ),
    ),
)

# A string property is bounded if it carries any of these constraints.
_STRING_BOUNDS = ("maxLength", "enum", "pattern", "format")


def detect_over_privilege(manifest: Manifest) -> list[Finding]:
    """Return the canonically-ordered over-privilege & schema findings."""
    findings: list[Finding] = []
    for tool in manifest.tools:
        for check in (_check_over_privilege, _check_missing_schema, _check_unbounded_schema):
            finding = check(tool)
            if finding is not None:
                findings.append(finding)
    # Each check returns ≤1 finding per tool, so for distinct tools this 2-key
    # sort is a total order. Duplicate-named tools (MCP allows them; R5b) can
    # collide on the key; both are kept deliberately (dropping one would hide a
    # finding — see F3 journal OQ) and the stable sort over the canonically
    # ordered manifest keeps output deterministic. (Matches poisoning.py.)
    findings.sort(key=lambda f: (f.entity_ref, f.finding_type))
    return findings


def _capability_text(tool: ToolRecord) -> str:
    # Property names are part of the surface (a `sql_query` param signals raw-sql);
    # underscores → spaces so multi-word seed phrases match property identifiers.
    props = tool.input_schema.get("properties") if isinstance(tool.input_schema, dict) else None
    # str(k): a hostile schema may carry non-string property keys (R6 no-crash).
    names = " ".join(str(k).replace("_", " ") for k in props) if isinstance(props, dict) else ""
    return f"{tool.name}\n{tool.description}\n{names}"


def _check_over_privilege(tool: ToolRecord) -> Finding | None:
    text = _capability_text(tool)
    caps = [cap for cap, patterns in _CAPABILITIES if any(p.search(text) for p in patterns)]
    if not caps:
        return None
    return Finding(
        "tool.over_privilege",
        f"tool:{tool.name}",
        "high",
        0.6,
        f"over-privileged capability: {', '.join(caps)}",
    )


def _check_missing_schema(tool: ToolRecord) -> Finding | None:
    schema = tool.input_schema
    # Empty {} has neither key, so the second clause subsumes it.
    if not isinstance(schema, dict) or ("type" not in schema and "properties" not in schema):
        return Finding(
            "tool.missing_schema",
            f"tool:{tool.name}",
            "medium",
            0.7,
            "no input validation declared (empty/absent input_schema)",
        )
    return None


def _check_unbounded_schema(tool: ToolRecord) -> Finding | None:
    schema = tool.input_schema
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties")
    # No declared properties → O2 owns the empty case; a no-arg tool is not unbounded.
    if not isinstance(props, dict) or not props:
        return None
    offenders: list[str] = []
    for name, spec in props.items():
        key = str(name)  # hostile schema may carry non-string keys (R6 no-crash)
        if not isinstance(spec, dict):
            offenders.append(key)
            continue
        ptype = spec.get("type")
        if ptype == "string" and not any(k in spec for k in _STRING_BOUNDS):
            offenders.append(key)
        elif ptype == "array" and "maxItems" not in spec:
            offenders.append(key)
    if schema.get("additionalProperties") is not False:
        offenders.append("additionalProperties")
    if not offenders:
        return None
    return Finding(
        "tool.unbounded_schema",
        f"tool:{tool.name}",
        "low",
        0.5,
        f"unbounded input(s): {', '.join(offenders)}",
    )


__all__ = ["detect_over_privilege"]
