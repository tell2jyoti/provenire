"""Poisoning detection (§3.2, feature F2, layer: engine).

Deterministic, no-LLM detection over a normalized ``Manifest``'s text fields.
Tool/prompt/resource descriptions are agent-facing instructions the model reads
but a human reviewer rarely sees, so they are a prime injection vector (MCP
"tool poisoning"; ``docs/references/mcp-security-best-practices.md``).

Scanned surface (§3.2): for each primitive, the concatenated human/agent-facing
text — tools & prompts: ``name`` + ``description``; resources: ``name`` +
``description`` (the ``uri`` is the entity_ref, not scanned). Findings are
emitted in a canonical order — sorted by ``(entity_ref, finding_type)`` — with
at most one finding per ``(entity_ref, finding_type)`` pair, so the same
``Manifest`` always yields the same list.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator

from ..enumerate.manifest import Manifest
from ..finding import Finding

# --- P2: hidden directive / instruction injection (extensible seed set) ---
# Each pattern is case-insensitive; DOTALL lets injected tag blocks span lines.
# Adding a pattern requires adding a test (§3.2). Every `.`-repetition is BOUNDED:
# detection runs over attacker-controlled text with no outer timeout, so an
# unbounded lazy `.*?` is a ReDoS / scanner-hang vector. The caps are far wider
# than any legitimate match while keeping every pattern linear.
_P2_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"ignore (?:all |the )?(?:previous|prior|above) instructions",
        r"disregard .{0,200}?instructions",
        r"do not (?:tell|inform|mention to|reveal to) the user",
        r"without (?:telling|informing|alerting) the user",
        r"system prompt",
        r"<important>.{0,4000}?</important>",
        r"<system>.{0,4000}?</system>",
        r"\[system\]",
    )
)

# --- P3: exfiltration — an egress verb paired with a destination OR a token ---
# Repetitions are bounded for the same ReDoS reason as P2; the URL/ftp branches
# capture the whole destination (host/path) so the rationale is actionable.
_P3_EGRESS = re.compile(
    r"\b(send|forward|post|upload|exfiltrate|email|leak|transmit)\b", re.IGNORECASE
)
_P3_DESTINATION = re.compile(
    r"(https?://\S{1,2048}|ftp://\S{1,2048}"
    r"|[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24})",
    re.IGNORECASE,
)
_P3_SENSITIVE = re.compile(
    r"(~/\.ssh|id_rsa|\.env|api[_ ]?key|password|secret|credentials|access[_ ]?token)",
    re.IGNORECASE,
)

# Ordinary whitespace is never "invisible" (§3.2 P1 carve-out).
_ALLOWED_CONTROL = frozenset("\t\n\r")


def detect_poisoning(manifest: Manifest) -> list[Finding]:
    """Return the canonically-ordered list of poisoning findings for ``manifest``."""
    findings: list[Finding] = []
    for entity_ref, text in _scanned_entities(manifest):
        findings.extend(_scan_text(entity_ref, text))
    # Each (entity_ref, finding_type) is unique *per scanned entity* (each rule
    # check returns ≤1 finding), so for distinct entities this 2-key sort is a
    # total order — equivalent to the spec's (entity_ref, finding_type, offset).
    # Duplicate-named primitives (MCP allows them; manifest R5b) can collide on
    # the key; both are kept deliberately (collapsing one would hide a poisoned
    # tool — see F2 journal OQ), and the sort stays *stable* over the already
    # canonically-ordered manifest (build_manifest, R5b) — so output is still
    # deterministic, just no longer a strict total order in that case.
    findings.sort(key=lambda f: (f.entity_ref, f.finding_type))
    return findings


def _scanned_entities(manifest: Manifest) -> Iterator[tuple[str, str]]:
    for tool in manifest.tools:
        yield f"tool:{tool.name}", f"{tool.name}\n{tool.description}"
    for resource in manifest.resources:
        yield f"resource:{resource.uri}", f"{resource.name}\n{resource.description}"
    for prompt in manifest.prompts:
        yield f"prompt:{prompt.name}", f"{prompt.name}\n{prompt.description}"


def _scan_text(entity_ref: str, text: str) -> list[Finding]:
    found = (
        _check_invisible_unicode(entity_ref, text),
        _check_directive(entity_ref, text),
        _check_exfiltration(entity_ref, text),
    )
    return [f for f in found if f is not None]


def _check_invisible_unicode(entity_ref: str, text: str) -> Finding | None:
    # dict preserves first-seen order and dedups repeated codepoints.
    codepoints: dict[str, None] = {}
    for ch in text:
        if ch in _ALLOWED_CONTROL:
            continue
        if unicodedata.category(ch) in ("Cc", "Cf"):
            codepoints[f"U+{ord(ch):04X}"] = None
    if not codepoints:
        return None
    return Finding(
        "tool.invisible_unicode",
        entity_ref,
        "high",
        0.95,
        f"invisible/non-printable character(s): {', '.join(codepoints)}",
    )


def _check_directive(entity_ref: str, text: str) -> Finding | None:
    matches = [m for m in (p.search(text) for p in _P2_PATTERNS) if m is not None]
    if not matches:
        return None
    first = min(matches, key=lambda m: m.start())  # earliest match by offset
    return Finding(
        "tool.poisoning",
        entity_ref,
        "high",
        0.85,
        f"hidden directive: {first.group(0)!r}",
    )


def _check_exfiltration(entity_ref: str, text: str) -> Finding | None:
    verb = _P3_EGRESS.search(text)
    if verb is None:
        return None
    target = _P3_DESTINATION.search(text) or _P3_SENSITIVE.search(text)
    if target is None:
        return None
    return Finding(
        "tool.exfiltration",
        entity_ref,
        "critical",
        0.8,
        f"exfiltration: egress {verb.group(0)!r} with {target.group(0)!r}",
    )
