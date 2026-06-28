"""R5 / R5a–c — manifest hash format, determinism, order-independence, drift."""

from __future__ import annotations

from typing import Any

from attestable_engine.enumerate.manifest import (
    PromptRecord,
    ResourceRecord,
    ToolRecord,
    build_manifest,
)


def _tools() -> list[ToolRecord]:
    return [
        ToolRecord(name="b", description="B", input_schema={}),
        ToolRecord(name="a", description="A", input_schema={"type": "string"}),
    ]


def test_hash_format_and_determinism() -> None:  # R5, R5a
    t = _tools()
    m1 = build_manifest(t, [], [], transport="stdio")
    m2 = build_manifest(list(t), [], [], transport="stdio")
    assert m1.manifest_hash.startswith("sha256:")
    assert len(m1.manifest_hash.split(":", 1)[1]) == 64
    assert m1.manifest_hash == m2.manifest_hash


def test_hash_order_independent() -> None:  # R5b
    t = _tools()
    m1 = build_manifest(t, [], [], transport="stdio")
    m2 = build_manifest(list(reversed(t)), [], [], transport="stdio")
    assert m1.manifest_hash == m2.manifest_hash


def test_hash_changes_on_tool_name() -> None:  # R5c
    base = build_manifest([ToolRecord("a", "d", {})], [], [], transport="stdio")
    diff = build_manifest([ToolRecord("a2", "d", {})], [], [], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_hash_changes_on_description() -> None:  # R5c
    base = build_manifest([ToolRecord("a", "d", {})], [], [], transport="stdio")
    diff = build_manifest([ToolRecord("a", "d2", {})], [], [], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_hash_changes_on_input_schema() -> None:  # R5c
    base = build_manifest([ToolRecord("a", "d", {})], [], [], transport="stdio")
    diff = build_manifest(
        [ToolRecord("a", "d", {"type": "object"})], [], [], transport="stdio"
    )
    assert base.manifest_hash != diff.manifest_hash


def test_transport_excluded_from_hash() -> None:  # design decision: transport not hashed
    a = build_manifest([ToolRecord("a", "d", {})], [], [], transport="stdio")
    b = build_manifest([ToolRecord("a", "d", {})], [], [], transport="streamable_http")
    assert a.manifest_hash == b.manifest_hash


def test_hash_order_independent_duplicate_tool_names() -> None:  # R5b (duplicate names)
    dup = [ToolRecord("dup", "A", {}), ToolRecord("dup", "B", {})]
    m1 = build_manifest(dup, [], [], transport="stdio")
    m2 = build_manifest(list(reversed(dup)), [], [], transport="stdio")
    assert m1.manifest_hash == m2.manifest_hash


def test_hash_order_independent_resources_and_prompts() -> None:  # R5b (resources/prompts)
    res = [ResourceRecord("file://b", "r", "x"), ResourceRecord("file://a", "r", "y")]
    pr = [PromptRecord("p2", "B"), PromptRecord("p1", "A")]
    m1 = build_manifest([], res, pr, transport="stdio")
    m2 = build_manifest([], list(reversed(res)), list(reversed(pr)), transport="stdio")
    assert m1.manifest_hash == m2.manifest_hash


def test_hash_changes_on_resource_uri() -> None:  # R5c
    base = build_manifest([], [ResourceRecord("file://a", "r", "d")], [], transport="stdio")
    diff = build_manifest([], [ResourceRecord("file://b", "r", "d")], [], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_hash_changes_on_resource_name() -> None:  # R5c
    base = build_manifest([], [ResourceRecord("file://a", "r", "d")], [], transport="stdio")
    diff = build_manifest([], [ResourceRecord("file://a", "r2", "d")], [], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_hash_changes_on_resource_description() -> None:  # R5c
    base = build_manifest([], [ResourceRecord("file://a", "r", "d")], [], transport="stdio")
    diff = build_manifest([], [ResourceRecord("file://a", "r", "d2")], [], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_hash_changes_on_prompt_name() -> None:  # R5c
    base = build_manifest([], [], [PromptRecord("p", "d")], transport="stdio")
    diff = build_manifest([], [], [PromptRecord("p2", "d")], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_hash_changes_on_prompt_description() -> None:  # R5c
    base = build_manifest([], [], [PromptRecord("p", "d")], transport="stdio")
    diff = build_manifest([], [], [PromptRecord("p", "d2")], transport="stdio")
    assert base.manifest_hash != diff.manifest_hash


def test_nested_schema_key_order_determinism() -> None:  # R5a/R5b (nested canonicalization)
    s1 = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "int"}}}
    s2 = {"properties": {"b": {"type": "int"}, "a": {"type": "string"}}, "type": "object"}
    m1 = build_manifest([ToolRecord("t", "d", s1)], [], [], transport="stdio")
    m2 = build_manifest([ToolRecord("t", "d", s2)], [], [], transport="stdio")
    assert m1.manifest_hash == m2.manifest_hash


def test_hash_changes_on_nested_schema_value() -> None:  # R5c (nested)
    s1 = {"type": "object", "properties": {"a": {"type": "string"}}}
    s2 = {"type": "object", "properties": {"a": {"type": "number"}}}
    m1 = build_manifest([ToolRecord("t", "d", s1)], [], [], transport="stdio")
    m2 = build_manifest([ToolRecord("t", "d", s2)], [], [], transport="stdio")
    assert m1.manifest_hash != m2.manifest_hash


def test_build_manifest_tolerates_nonstring_keys() -> None:  # R6 (hash layer never raises)
    schema: dict[Any, Any] = {(1, 2): "a"}
    m = build_manifest([ToolRecord("t", "d", schema)], [], [], transport="stdio")
    assert m.manifest_hash.startswith("sha256:")
