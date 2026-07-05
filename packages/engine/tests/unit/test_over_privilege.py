"""§3.3 — over-privilege & schema (O0 clean, O1 capability, O2 missing, O3 unbounded)."""

from __future__ import annotations

from typing import Any, Callable

import pytest

from provenire_engine import (
    Finding,
    PromptRecord,
    ResourceRecord,
    ToolRecord,
    detect_over_privilege,
)

MakeManifest = Callable[..., Any]

BOUNDED = {"type": "object", "properties": {}, "additionalProperties": False}


def _op(fs: list[Finding]) -> list[Finding]:
    return [f for f in fs if f.finding_type == "tool.over_privilege"]


# --- O1: over-privileged capability ---

@pytest.mark.parametrize(
    "desc,cap",
    [
        # shell — one witness per seed alternative
        ("Execute a shell command on the host", "shell"),
        ("Spawn a bash subprocess", "shell"),
        ("Invokes /bin/sh directly", "shell"),
        ("Launches /bin/bash", "shell"),
        ("Calls os.system to run it", "shell"),
        ("Executes a system command", "shell"),
        ("Run a command on the host", "shell"),
        ("Runs arbitrary code", "shell"),
        # file-write
        ("Write the file to disk", "file-write"),
        ("Create a file at the path", "file-write"),
        ("Delete a file at the given path", "file-write"),
        ("Remove the directory", "file-write"),
        ("Overwrite a file", "file-write"),
        ("Rename the path", "file-write"),
        ("Modify a file in place", "file-write"),
        ("Append the file with data", "file-write"),
        ("Runs chmod on a path", "file-write"),
        ("Calls mkdir for you", "file-write"),
        ("Calls rmdir for you", "file-write"),
        ("Calls unlink on it", "file-write"),
        ("Performs a filesystem write", "file-write"),
        # raw-sql (phrases case-insensitive; keywords case-sensitive)
        ("Run a raw SQL query", "raw-sql"),
        ("Execute a query against the DB", "raw-sql"),
        ("Runs an arbitrary query", "raw-sql"),
        ("Performs a database query", "raw-sql"),
        ("Runs a SELECT statement", "raw-sql"),
        ("Issues a DROP on a table", "raw-sql"),
        ("Runs DELETE FROM the table", "raw-sql"),
        ("Performs INSERT INTO the log", "raw-sql"),
        # egress
        ("Make an HTTP request to a URL", "egress"),
        ("Fetch a URL and return it", "egress"),
        ("Makes an outbound connection", "egress"),
        ("Posts to a webhook", "egress"),
        ("Issues a network request", "egress"),
        ("Performs an api call", "egress"),
        ("Runs curl under the hood", "egress"),
        ("Connects to an external endpoint", "egress"),
    ],
)
def test_o1_capability_detected(make_manifest: MakeManifest, desc: str, cap: str) -> None:
    m = make_manifest(tools=[ToolRecord("t", desc, BOUNDED)])
    fs = _op(detect_over_privilege(m))
    assert len(fs) == 1
    assert fs[0].finding_type == "tool.over_privilege"
    assert fs[0].severity == "high"
    assert fs[0].confidence == 0.6
    assert cap in fs[0].rationale


@pytest.mark.parametrize("prop,cap", [("sql_query", "raw-sql"), ("run_command", "shell")])
def test_o1_property_name_is_a_capability_signal(
    make_manifest: MakeManifest, prop: str, cap: str
) -> None:
    # A terse tool whose schema exposes a hazardous parameter is over-privileged.
    schema = {
        "type": "object",
        "properties": {prop: {"type": "string", "maxLength": 200}},
        "additionalProperties": False,
    }
    m = make_manifest(tools=[ToolRecord("run", "Runs a task.", schema)])
    fs = _op(detect_over_privilege(m))
    assert len(fs) == 1
    assert cap in fs[0].rationale


@pytest.mark.parametrize(
    "desc",
    [
        "Select a row to display to the user",  # case-sensitive SELECT must not FP
        "Drop a note for the user",
    ],
)
def test_o1_sql_keywords_are_case_sensitive(make_manifest: MakeManifest, desc: str) -> None:
    fs = detect_over_privilege(make_manifest(tools=[ToolRecord("t", desc, BOUNDED)]))
    assert all(f.finding_type != "tool.over_privilege" for f in fs)


def test_o1_multiple_capabilities_one_finding(make_manifest: MakeManifest) -> None:
    m = make_manifest(
        tools=[ToolRecord("t", "Execute a shell command and write the file to disk", BOUNDED)]
    )
    fs = _op(detect_over_privilege(m))
    assert len(fs) == 1
    assert "shell" in fs[0].rationale
    assert "file-write" in fs[0].rationale


@pytest.mark.parametrize(
    "desc",
    [
        "Send an email to a recipient.",
        "Returns the user's calendar events.",
    ],
)
def test_o1_benign_not_flagged(make_manifest: MakeManifest, desc: str) -> None:
    schema = {
        "type": "object",
        "properties": {"x": {"type": "string", "maxLength": 10}},
        "additionalProperties": False,
    }
    fs = detect_over_privilege(make_manifest(tools=[ToolRecord("t", desc, schema)]))
    assert all(f.finding_type != "tool.over_privilege" for f in fs)


# --- O2: missing input validation ---

def test_o2_empty_schema_flagged(make_manifest: MakeManifest) -> None:
    m = make_manifest(tools=[ToolRecord("t", "A tool.", {})])
    fs = [f for f in detect_over_privilege(m) if f.finding_type == "tool.missing_schema"]
    assert len(fs) == 1
    assert fs[0].severity == "medium"
    assert fs[0].confidence == 0.7
    assert "validation" in fs[0].rationale.lower()


def test_o2_schema_lacking_type_and_properties_flagged(make_manifest: MakeManifest) -> None:
    # Non-empty dict that still declares no type and no properties → missing.
    m = make_manifest(tools=[ToolRecord("t", "x", {"description": "foo"})])
    fs = [f for f in detect_over_privilege(m) if f.finding_type == "tool.missing_schema"]
    assert len(fs) == 1


def test_o2_type_only_schema_not_missing(make_manifest: MakeManifest) -> None:
    # {"type":"object"} declares a type → not O2 (pins the current boundary; the
    # "open object with no properties" hole is a journal OQ, not O2).
    m = make_manifest(tools=[ToolRecord("t", "x", {"type": "object"})])
    assert all(f.finding_type != "tool.missing_schema" for f in detect_over_privilege(m))


def test_o2_no_arg_tool_not_flagged(make_manifest: MakeManifest) -> None:
    # A genuine no-arg tool declares {"type":"object","properties":{}} — has a schema.
    m = make_manifest(tools=[ToolRecord("t", "No args.", BOUNDED)])
    assert all(f.finding_type != "tool.missing_schema" for f in detect_over_privilege(m))


def test_o2_real_schema_not_flagged(make_manifest: MakeManifest) -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "maxLength": 5}},
        "additionalProperties": False,
    }
    m = make_manifest(tools=[ToolRecord("t", "x", schema)])
    assert all(f.finding_type != "tool.missing_schema" for f in detect_over_privilege(m))


# --- O3: unbounded input validation ---

def test_o3_unbounded_string_flagged(make_manifest: MakeManifest) -> None:
    schema = {"type": "object", "properties": {"q": {"type": "string"}}, "additionalProperties": False}
    m = make_manifest(tools=[ToolRecord("t", "x", schema)])
    fs = [f for f in detect_over_privilege(m) if f.finding_type == "tool.unbounded_schema"]
    assert len(fs) == 1
    assert fs[0].severity == "low"
    assert fs[0].confidence == 0.5
    assert "q" in fs[0].rationale


def test_o3_unbounded_array_flagged(make_manifest: MakeManifest) -> None:
    schema = {
        "type": "object",
        "properties": {"items": {"type": "array"}},
        "additionalProperties": False,
    }
    m = make_manifest(tools=[ToolRecord("t", "x", schema)])
    fs = [f for f in detect_over_privilege(m) if f.finding_type == "tool.unbounded_schema"]
    assert len(fs) == 1
    assert "items" in fs[0].rationale


def test_o3_open_additional_properties_flagged(make_manifest: MakeManifest) -> None:
    # Bounded property but additionalProperties not false → arbitrary extra keys.
    schema = {"type": "object", "properties": {"a": {"type": "string", "maxLength": 5}}}
    m = make_manifest(tools=[ToolRecord("t", "x", schema)])
    fs = [f for f in detect_over_privilege(m) if f.finding_type == "tool.unbounded_schema"]
    assert len(fs) == 1
    assert "additionalProperties" in fs[0].rationale


@pytest.mark.parametrize(
    "constraint",
    [
        {"maxLength": 10},
        {"enum": ["a", "b"]},
        {"pattern": "^[a-z]+$"},
        {"format": "email"},
    ],
)
def test_o3_bounded_string_not_flagged(
    make_manifest: MakeManifest, constraint: dict[str, Any]
) -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", **constraint}},
        "additionalProperties": False,
    }
    fs = detect_over_privilege(make_manifest(tools=[ToolRecord("t", "x", schema)]))
    assert all(f.finding_type != "tool.unbounded_schema" for f in fs)


def test_o3_bounded_array_not_flagged(make_manifest: MakeManifest) -> None:
    schema = {
        "type": "object",
        "properties": {"items": {"type": "array", "maxItems": 100}},
        "additionalProperties": False,
    }
    fs = detect_over_privilege(make_manifest(tools=[ToolRecord("t", "x", schema)]))
    assert all(f.finding_type != "tool.unbounded_schema" for f in fs)


def test_non_string_property_keys_do_not_crash(make_manifest: MakeManifest) -> None:
    # A hostile schema may carry non-string property keys (R6: never crash).
    schema = {"type": "object", "properties": {1: {"type": "string"}}, "additionalProperties": False}
    fs = detect_over_privilege(make_manifest(tools=[ToolRecord("t", "x", schema)]))
    assert isinstance(fs, list)
    unbounded = [f for f in fs if f.finding_type == "tool.unbounded_schema"]
    assert len(unbounded) == 1
    assert "1" in unbounded[0].rationale


# --- O2/O3 mutual exclusivity ---

def test_missing_and_unbounded_are_mutually_exclusive(make_manifest: MakeManifest) -> None:
    m = make_manifest(tools=[ToolRecord("t", "x", {})])
    fts = {f.finding_type for f in detect_over_privilege(m)}
    assert "tool.missing_schema" in fts
    assert "tool.unbounded_schema" not in fts


# --- scanned surface: tools only ---

def test_only_tools_scanned(make_manifest: MakeManifest) -> None:
    m = make_manifest(
        resources=[ResourceRecord("file://x", "execute shell command", "run a raw sql query")],
        prompts=[PromptRecord("p", "write the file to disk")],
    )
    assert detect_over_privilege(m) == []


# --- multi-finding, dedup, determinism / canonical order ---

def test_two_findings_same_tool(make_manifest: MakeManifest) -> None:
    schema = {"type": "object", "properties": {"cmd": {"type": "string"}}, "additionalProperties": False}
    m = make_manifest(tools=[ToolRecord("dangerous", "Execute a shell command", schema)])
    fs = detect_over_privilege(m)
    assert {f.finding_type for f in fs} == {"tool.over_privilege", "tool.unbounded_schema"}
    assert all(f.entity_ref == "tool:dangerous" for f in fs)
    assert len(fs) == 2


def test_canonical_order_and_determinism(make_manifest: MakeManifest) -> None:
    m = make_manifest(
        tools=[
            ToolRecord("b_tool", "Execute a shell command", {}),
            ToolRecord("a_tool", "Execute a shell command", {}),
        ]
    )
    fs = detect_over_privilege(m)
    refs = [(f.entity_ref, f.finding_type) for f in fs]
    assert refs == sorted(refs)
    assert detect_over_privilege(m) == detect_over_privilege(m)


def test_o0_benign_manifest_silent(make_manifest: MakeManifest) -> None:
    m = make_manifest(
        tools=[
            ToolRecord(
                "send_email",
                "Send an email to a recipient.",
                {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "format": "email", "maxLength": 254},
                        "body": {"type": "string", "maxLength": 10000},
                    },
                    "additionalProperties": False,
                },
            ),
            ToolRecord("get_cal", "Returns the user's calendar events.", BOUNDED),
        ]
    )
    assert detect_over_privilege(m) == []


def test_f3_acceptance(make_manifest: MakeManifest) -> None:
    schema = {"type": "object", "properties": {"q": {"type": "string"}}, "additionalProperties": False}
    m = make_manifest(
        tools=[ToolRecord("danger", "Run a raw SQL query and make an HTTP request", schema)]
    )
    fs = detect_over_privilege(m)
    assert isinstance(fs, list) and all(isinstance(f, Finding) for f in fs)
    for f in fs:
        assert f.finding_type in {
            "tool.over_privilege",
            "tool.missing_schema",
            "tool.unbounded_schema",
        }
        assert f.severity in {"critical", "high", "medium", "low"}
        assert 0.0 <= f.confidence <= 1.0
        assert f.entity_ref.startswith("tool:")
        assert f.rationale
    refs = [(f.entity_ref, f.finding_type) for f in fs]
    assert refs == sorted(refs)
