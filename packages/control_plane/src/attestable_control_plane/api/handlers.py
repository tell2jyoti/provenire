"""POST /scan orchestrator (scan-api-spec §2, the request flow).

Order is load-bearing (spec flow, S6): parse body (A1/A2) -> validate target as
an absolute http(s) URL (A3) -> transport (A4) -> mode (A5, semantic -> 402) ->
**SSRF resolve + classify (S1-S6.1) before any socket** -> rate-limit (R1) ->
run the engine's F1->F5 pipeline under a whole-request deadline (S5) -> shape the
200 with rate headers (A6-A11, R2).

The transport/connect/resolver/rate-limiter are all injected (app factory), so
this is exercised in-process with no live DNS, socket, or wall clock. Reuses
attestable_engine unchanged; imports no regulation and no cli (architecture law).
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable, Sequence

from attestable_engine import (
    ScanResult,
    TargetUnreachable as EngineUnreachable,
    build_report,
    detect_over_privilege,
    detect_poisoning,
    scan,
    score_findings,
)
from attestable_engine.connect.session import Session, Transport
from starlette.requests import Request
from starlette.responses import JSONResponse

from .errors import InvalidTarget, TargetUnreachable, TierRequired, safe_message
from .models import FindingModel, ScanResponse, Summary
from .rate_limit import InMemoryRateLimiter
from .ssrf import resolve_and_validate

Connect = Callable[[str, Transport, float], Awaitable[Session]]
Resolver = Callable[[str], Sequence[str]]


def _client_ip(request: Request, *, trust_forwarded_for: bool) -> str:
    """Per-IP rate-limit key (R1).

    ``X-Forwarded-For`` is client-supplied and spoofable, so a direct-facing
    deployment MUST NOT trust it — otherwise an attacker rotates the header to
    mint a fresh quota per value and defeats the limit. It is honoured only when
    the app is configured behind a trusted proxy (``trust_forwarded_for``);
    otherwise the authenticated peer address is authoritative. A blank/whitespace
    header falls through to the peer so malformed requests aren't bucketed together.
    """
    if trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else "unknown"


async def handle_scan(
    request: Request,
    *,
    connect: Connect,
    resolver: Resolver,
    rate_limiter: InMemoryRateLimiter,
    timeout: float,
    trust_forwarded_for: bool = False,
) -> JSONResponse:
    # A1/A2 — body must be a JSON object.
    try:
        payload = await request.json()
    except Exception as exc:  # noqa: BLE001 — any decode failure is a client error
        raise InvalidTarget("request body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise InvalidTarget("request body must be a JSON object")

    # A3 — target present and an absolute http(s) URL (shape checked in SSRF layer).
    target = payload.get("target")
    if not isinstance(target, str) or not target.strip():
        raise InvalidTarget("target is required")

    # A4 — transport: default streamable_http; stdio is CLI-only; else unknown.
    transport = payload.get("transport", "streamable_http")
    if transport != "streamable_http":
        raise InvalidTarget("transport must be streamable_http (stdio is CLI-only)")

    # A5 — mode: default deterministic; semantic is a paid tier; else unknown.
    mode = payload.get("mode", "deterministic")
    if mode == "semantic":
        raise TierRequired("semantic mode requires a paid tier")
    if mode != "deterministic":
        raise InvalidTarget("mode must be deterministic")

    # S1-S6.1 — resolve + classify BEFORE any socket is opened (fail closed).
    resolve_and_validate(target, resolver)

    # R1 — record the hit (raises RateLimited -> 429 with headers via the handler).
    rate = rate_limiter.check_and_record(
        _client_ip(request, trust_forwarded_for=trust_forwarded_for)
    )

    # S5 — the whole F1->F5 pipeline runs under one deadline; timeout/refused -> 408.
    async def _pipeline() -> tuple[str, ScanResponse]:
        session = await connect(target, "streamable_http", timeout)
        manifest = await scan(session, transport="streamable_http", timeout=timeout)
        findings = detect_poisoning(manifest) + detect_over_privilege(manifest)
        result = score_findings(findings)
        report = build_report(manifest, result)
        return report.json, _shape(manifest.manifest_hash, result)

    try:
        _, response = await asyncio.wait_for(_pipeline(), timeout)
    except (EngineUnreachable, TimeoutError, asyncio.TimeoutError) as exc:
        # E6 — the target string may carry secrets/control bytes; use a fixed message.
        raise TargetUnreachable("target could not be reached") from exc

    headers = {
        "X-RateLimit-Limit": str(rate.limit),
        "X-RateLimit-Remaining": str(rate.remaining),
        "X-RateLimit-Reset": str(rate.reset),
    }
    return JSONResponse(status_code=200, content=response.model_dump(), headers=headers)


def _shape(server_hash: str, result: ScanResult) -> ScanResponse:
    """Map the engine ScanResult onto the wire response (A6-A11)."""
    score = result.score
    summary = Summary(
        critical=score.counts["critical"],
        high=score.counts["high"],
        medium=score.counts["medium"],
        low=score.counts["low"],
        gate=score.gate,
    )
    findings = [
        FindingModel(
            id=f"f{i}",
            type=f.finding_type,
            severity=f.severity,
            confidence=f.confidence,
            # E6 — findings originate from a hostile server; strip control bytes.
            entity=safe_message(f.entity_ref),
            rationale=safe_message(f.rationale),
        )
        for i, f in enumerate(result.findings, start=1)
    ]
    return ScanResponse(
        scan_id="scn_" + secrets.token_hex(16),
        server_hash=server_hash,
        summary=summary,
        findings=findings,
        report_url=None,
    )


__all__ = ["handle_scan"]
