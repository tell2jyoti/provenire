"""FastAPI app factory for the scan API (scan-api-spec §2/§5).

`create_app` takes the injectable seams — the transport `connect`, the DNS
`resolver`, an optional `rate_limiter`, and the whole-request `timeout` — so the
suite drives the API in-process with no live network or clock. Every `ApiError`
is rendered to `{"error": {"code", "message"}}` with a safe message (E1-E6); a
`RateLimited` additionally carries the `X-RateLimit-*` headers (R2). Imports
provenire_engine (allowed) but never cli, and names no regulation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from provenire_engine.connect.session import Session, Transport
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from .errors import ApiError, RateLimited, safe_message
from .handlers import handle_scan
from .rate_limit import InMemoryRateLimiter

Connect = Callable[[str, Transport, float], Awaitable[Session]]
Resolver = Callable[[str], Sequence[str]]


def create_app(
    *,
    connect: Connect,
    resolver: Resolver,
    rate_limiter: InMemoryRateLimiter | None = None,
    timeout: float = 10.0,
    trust_forwarded_for: bool = False,
) -> FastAPI:
    limiter = rate_limiter if rate_limiter is not None else InMemoryRateLimiter()
    app = FastAPI()
    app.state.scan_timeout = timeout  # S5 — inspectable default deadline.

    @app.post("/scan")
    async def scan_endpoint(request: Request) -> JSONResponse:
        return await handle_scan(
            request, connect=connect, resolver=resolver,
            rate_limiter=limiter, timeout=timeout,
            trust_forwarded_for=trust_forwarded_for,
        )

    @app.exception_handler(ApiError)
    async def _on_api_error(_request: Request, exc: ApiError) -> JSONResponse:
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimited):  # R2 — rate headers ride the 429 too.
            headers = {
                "X-RateLimit-Limit": str(exc.limit),
                "X-RateLimit-Remaining": str(exc.remaining),
                "X-RateLimit-Reset": str(exc.reset),
            }
        return JSONResponse(
            status_code=exc.http_status,
            content={"error": {"code": exc.code, "message": safe_message(exc.message)}},
            headers=headers,
        )

    return app


__all__ = ["create_app"]
