"""Handshake + timeout translation (R1, R2)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable
from typing import TypeVar

from .errors import TargetUnreachable
from .session import Session

T = TypeVar("T")


async def bounded(awaitable: Awaitable[T], timeout: float) -> T:
    """Await `awaitable`, mapping timeout or connection failure to `TargetUnreachable` (R2).

    Scoped to the genuine "unreachable" failures: `TimeoutError` (the `wait_for`
    deadline), `ConnectionError` (refused / reset / aborted), and `socket.gaierror`
    (DNS). Other `OSError`s (e.g. a bad stdio command's `FileNotFoundError`) and
    `CancelledError` propagate unchanged rather than being mislabeled.
    """
    try:
        return await asyncio.wait_for(awaitable, timeout)
    except (TimeoutError, ConnectionError, socket.gaierror) as exc:
        raise TargetUnreachable("MCP target unreachable") from exc


async def handshake(session: Session, *, timeout: float) -> None:
    """Initialize the session before any enumeration (R1)."""
    await bounded(session.initialize(), timeout)
