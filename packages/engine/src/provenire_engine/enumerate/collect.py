"""Enumerate all three primitive kinds (R4), each timeout-bounded (R2)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..connect.handshake import bounded
from ..connect.session import Session


def _as_list(value: Any) -> list[Any]:
    # A server returning a non-list (e.g. None) is treated as empty (R4/R6).
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return []


async def collect(
    session: Session, *, timeout: float
) -> tuple[Sequence[Any], Sequence[Any], Sequence[Any]]:
    """Return (tools, resources, prompts) — all three, never a subset (R4)."""
    tools = _as_list(await bounded(session.list_tools(), timeout))
    resources = _as_list(await bounded(session.list_resources(), timeout))
    prompts = _as_list(await bounded(session.list_prompts(), timeout))
    return tools, resources, prompts
