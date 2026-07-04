"""Per-IP rate limiting for the free scan tier (scan-api-spec §6, R1-R3).

In-memory sliding window — one process this trip (TDD §03: single EC2 box); a
shared store lands with persistence. The clock is injected so tests advance time
deterministically instead of sleeping (R3).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from .errors import RateLimited


@dataclass(frozen=True)
class RateInfo:
    """The `X-RateLimit-*` header values for a permitted request (R2)."""

    limit: int
    remaining: int
    reset: int  # unix timestamp when the caller's window frees up


class InMemoryRateLimiter:
    def __init__(
        self, limit: int = 30, window_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._hits: dict[str, list[float]] = {}

    def check_and_record(self, client_ip: str) -> RateInfo:
        """Record one hit for `client_ip`; raise RateLimited if over the window limit."""
        now = self._clock()
        window_start = now - self.window_seconds
        hits = [t for t in self._hits.get(client_ip, ()) if t > window_start]
        # Window frees when the oldest hit ages out (or one window from now if idle).
        reset = int((hits[0] if hits else now) + self.window_seconds)
        if len(hits) >= self.limit:
            self._hits[client_ip] = hits
            raise RateLimited(limit=self.limit, remaining=0, reset=reset)
        hits.append(now)
        self._hits[client_ip] = hits
        return RateInfo(limit=self.limit, remaining=self.limit - len(hits), reset=reset)
