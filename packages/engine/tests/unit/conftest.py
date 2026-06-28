"""Shared in-memory test doubles for the engine unit suite.

No network and no `mcp` SDK: the `FakeSession` structurally satisfies the
engine-facing `Session` protocol (initialize / list_tools / list_resources /
list_prompts) and records call order so tests can assert the handshake (R1)
happens before enumeration. Primitive builders intentionally omit optional
attributes so normalization defaults (R6) can be exercised.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from attestable_engine.enumerate.manifest import (
    Manifest,
    PromptRecord,
    ResourceRecord,
    ToolRecord,
    build_manifest,
)


class FakeSession:
    """In-memory stand-in for an MCP client session.

    Records every call in ``calls`` (in order). Knobs for exercising failure
    modes:
    - ``raise_on`` names a method that raises ``exc`` (default ``TimeoutError``)
      — R2 translation.
    - ``slow_on`` names a method that ``await``s ``delay`` seconds before
      returning — R2 *bound* (a real timeout must cut it off).
    - ``none_lists`` makes the three ``list_*`` methods return ``None`` instead
      of a list — R4/R6 "non-list treated as empty".
    """

    def __init__(
        self,
        tools: list[Any] | None = None,
        resources: list[Any] | None = None,
        prompts: list[Any] | None = None,
        *,
        raise_on: str | None = None,
        exc: BaseException | None = None,
        slow_on: str | None = None,
        delay: float = 0.0,
        none_lists: bool = False,
    ) -> None:
        self._tools = list(tools or [])
        self._resources = list(resources or [])
        self._prompts = list(prompts or [])
        self._raise_on = raise_on
        self._exc: BaseException = exc or TimeoutError("simulated timeout")
        self._slow_on = slow_on
        self._delay = delay
        self._none_lists = none_lists
        self.calls: list[str] = []

    async def _record(self, name: str) -> None:
        self.calls.append(name)
        if self._slow_on == name:
            await asyncio.sleep(self._delay)
        if self._raise_on == name:
            raise self._exc

    async def initialize(self) -> Any:
        await self._record("initialize")

    async def list_tools(self) -> Any:
        await self._record("list_tools")
        return None if self._none_lists else list(self._tools)

    async def list_resources(self) -> Any:
        await self._record("list_resources")
        return None if self._none_lists else list(self._resources)

    async def list_prompts(self) -> Any:
        await self._record("list_prompts")
        return None if self._none_lists else list(self._prompts)


@pytest.fixture
def make_tool() -> Callable[..., SimpleNamespace]:
    def _make(name: str, **kw: Any) -> SimpleNamespace:
        ns = SimpleNamespace(name=name)
        if "description" in kw:
            ns.description = kw["description"]
        if "input_schema" in kw:
            ns.input_schema = kw["input_schema"]
        return ns

    return _make


@pytest.fixture
def make_resource() -> Callable[..., SimpleNamespace]:
    def _make(uri: str, name: str, **kw: Any) -> SimpleNamespace:
        ns = SimpleNamespace(uri=uri, name=name)
        if "description" in kw:
            ns.description = kw["description"]
        return ns

    return _make


@pytest.fixture
def make_prompt() -> Callable[..., SimpleNamespace]:
    def _make(name: str, **kw: Any) -> SimpleNamespace:
        ns = SimpleNamespace(name=name)
        if "description" in kw:
            ns.description = kw["description"]
        return ns

    return _make


@pytest.fixture
def fake_session() -> Callable[..., FakeSession]:
    def _make(**kw: Any) -> FakeSession:
        return FakeSession(**kw)

    return _make


@pytest.fixture
def make_manifest() -> Callable[..., Manifest]:
    """Build a Manifest directly from records — no Session, no network (F2 detect tests)."""

    def _make(
        *,
        tools: Sequence[ToolRecord] = (),
        resources: Sequence[ResourceRecord] = (),
        prompts: Sequence[PromptRecord] = (),
    ) -> Manifest:
        return build_manifest(list(tools), list(resources), list(prompts), transport="stdio")

    return _make
