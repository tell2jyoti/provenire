"""R6 — normalization defaults for absent optional fields."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Callable

from attestable_engine.enumerate.normalize import (
    to_prompt_record,
    to_resource_record,
    to_tool_record,
)


def test_tool_defaults_when_fields_absent(
    make_tool: Callable[..., SimpleNamespace],
) -> None:  # R6
    rec = to_tool_record(make_tool("send_mail"))
    assert rec.name == "send_mail"
    assert rec.description == ""
    assert rec.input_schema == {}


def test_tool_none_fields_normalize_to_defaults(
    make_tool: Callable[..., SimpleNamespace],
) -> None:  # R6
    rec = to_tool_record(make_tool("t", description=None, input_schema=None))
    assert rec.description == ""
    assert rec.input_schema == {}


def test_tool_preserves_present_fields(
    make_tool: Callable[..., SimpleNamespace],
) -> None:  # R6
    schema = {"type": "object", "properties": {}}
    rec = to_tool_record(make_tool("t", description="does x", input_schema=schema))
    assert rec.description == "does x"
    assert rec.input_schema == schema


def test_resource_and_prompt_default_description(
    make_resource: Callable[..., SimpleNamespace],
    make_prompt: Callable[..., SimpleNamespace],
) -> None:  # R6
    r = to_resource_record(make_resource("file://a", "a"))
    p = to_prompt_record(make_prompt("greet"))
    assert r.description == ""
    assert p.description == ""


def test_nonstring_name_coerced_not_dropped(
    make_tool: Callable[..., SimpleNamespace],
) -> None:  # R6 (present-but-malformed → coerced)
    rec = to_tool_record(make_tool(123, description=456))
    assert rec.name == "123"
    assert rec.description == "456"


def test_nonstring_uri_coerced(
    make_resource: Callable[..., SimpleNamespace],
) -> None:  # R6 (e.g. a real SDK AnyUrl)
    rec = to_resource_record(make_resource(SimpleNamespace(__str__=lambda self: "file://x"), "r"))
    assert isinstance(rec.uri, str)


def test_nondict_input_schema_defaults_to_empty(
    make_tool: Callable[..., SimpleNamespace],
) -> None:  # R6 (a non-object is not a schema)
    rec = to_tool_record(make_tool("t", input_schema=["not", "a", "dict"]))
    assert rec.input_schema == {}


def test_str_coercion_never_raises_on_hostile_object() -> None:  # R6 (never crash)
    class Raiser:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    rec = to_tool_record(SimpleNamespace(name=Raiser(), description=Raiser()))
    assert rec.name == ""
    assert rec.description == ""


def test_schema_rejects_nonstring_keyed_dict(
    make_tool: Callable[..., SimpleNamespace],
) -> None:  # R6 defense-in-depth
    schema: dict[Any, Any] = {(1, 2): "a"}
    rec = to_tool_record(make_tool("t", input_schema=schema))
    assert rec.input_schema == {}
