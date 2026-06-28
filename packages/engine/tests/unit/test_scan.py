"""R1–R4 + F1 acceptance — the public `scan` entrypoint over a fake Session."""

from __future__ import annotations

import asyncio
from typing import Any, Callable

import pytest

from attestable_engine import Transport, scan
from attestable_engine.connect.errors import TargetUnreachable


def test_initialize_before_enumeration(
    fake_session: Callable[..., Any],
    make_tool: Callable[..., Any],
) -> None:  # R1
    s = fake_session(tools=[make_tool("t")])
    asyncio.run(scan(s, transport="stdio"))
    assert s.calls[0] == "initialize"
    assert set(s.calls[1:]) == {"list_tools", "list_resources", "list_prompts"}


def test_enumerates_all_three(
    fake_session: Callable[..., Any],
    make_tool: Callable[..., Any],
    make_resource: Callable[..., Any],
    make_prompt: Callable[..., Any],
) -> None:  # R4
    s = fake_session(
        tools=[make_tool("t")],
        resources=[make_resource("file://u", "r")],
        prompts=[make_prompt("p")],
    )
    m = asyncio.run(scan(s, transport="stdio"))
    assert [t.name for t in m.tools] == ["t"]
    assert [r.name for r in m.resources] == ["r"]
    assert [p.name for p in m.prompts] == ["p"]


def test_empty_server_yields_present_empty_manifest(
    fake_session: Callable[..., Any],
) -> None:  # R4 (empty)
    m = asyncio.run(scan(fake_session(), transport="stdio"))
    assert list(m.tools) == []
    assert list(m.resources) == []
    assert list(m.prompts) == []
    assert m.manifest_hash.startswith("sha256:")


def test_none_lists_treated_as_empty(
    fake_session: Callable[..., Any],
) -> None:  # R4/R6 (non-list → empty, no crash)
    m = asyncio.run(scan(fake_session(none_lists=True), transport="stdio"))
    assert list(m.tools) == []
    assert list(m.resources) == []
    assert list(m.prompts) == []


@pytest.mark.parametrize(
    "method", ["initialize", "list_tools", "list_resources", "list_prompts"]
)
def test_real_timeout_bound_cuts_off_slow_call(
    fake_session: Callable[..., Any], method: str
) -> None:  # R2 (the actual bound on every call, not just translation)
    s = fake_session(slow_on=method, delay=5.0)
    with pytest.raises(TargetUnreachable):
        asyncio.run(scan(s, transport="stdio", timeout=0.01))


def test_connection_failure_maps_to_target_unreachable(
    fake_session: Callable[..., Any],
) -> None:  # R2 (refused/DNS/reset → unreachable, not raw OSError)
    s = fake_session(raise_on="initialize", exc=ConnectionRefusedError("refused"))
    with pytest.raises(TargetUnreachable):
        asyncio.run(scan(s, transport="stdio"))


@pytest.mark.parametrize("transport", ["stdio", "streamable_http"])
def test_accepts_both_transports(
    fake_session: Callable[..., Any], transport: Transport
) -> None:  # R3
    m = asyncio.run(scan(fake_session(), transport=transport))
    assert m.transport == transport


@pytest.mark.parametrize(
    "raise_on", ["initialize", "list_tools", "list_resources", "list_prompts"]
)
def test_timeout_maps_to_target_unreachable(
    fake_session: Callable[..., Any], raise_on: str
) -> None:  # R2
    s = fake_session(raise_on=raise_on, exc=TimeoutError("boom"))
    with pytest.raises(TargetUnreachable):
        asyncio.run(scan(s, transport="stdio"))


def test_acceptance_no_findings_and_normalized(
    fake_session: Callable[..., Any],
    make_tool: Callable[..., Any],
) -> None:  # F1 acceptance
    s = fake_session(tools=[make_tool("send_mail")])
    m = asyncio.run(scan(s, transport="stdio"))
    assert m.tools[0].description == ""
    assert m.tools[0].input_schema == {}
    assert not hasattr(m, "findings")
