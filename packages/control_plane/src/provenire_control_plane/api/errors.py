"""HTTP error model for the scan API (scan-api-spec §5, E1-E6).

Each `ApiError` subclass carries its own HTTP status + machine `code`; the app's
exception handler renders `{"error": {"code", "message"}}`. Messages are passed
through `safe_message` so attacker-controlled target bytes can never inject
terminal/control sequences, and callers keep resolved internal IPs out of the
text (E6).
"""

from __future__ import annotations


class ApiError(Exception):
    """Base for every mapped error. Not raised directly."""

    code: str = "error"
    http_status: int = 500

    def __init__(self, message: str = "") -> None:
        super().__init__(message)
        self.message = message


class InvalidTarget(ApiError):  # E1
    code = "invalid_target"
    http_status = 400


class BlockedTarget(ApiError):  # E2
    code = "blocked_target"
    http_status = 403


class TargetUnreachable(ApiError):  # E3
    code = "target_unreachable"
    http_status = 408


class RateLimited(ApiError):  # E4
    code = "rate_limited"
    http_status = 429

    def __init__(
        self, message: str = "rate limit exceeded", *, limit: int = 0, remaining: int = 0,
        reset: int = 0,
    ) -> None:
        super().__init__(message)
        self.limit = limit
        self.remaining = remaining
        self.reset = reset


class TierRequired(ApiError):  # E5
    code = "tier_required"
    http_status = 402


def safe_message(text: str) -> str:
    """Strip C0/C1 control bytes + DEL (mirrors the CLI's `_safe`, E6).

    Finding/target text originates from a hostile source; rendered raw an ESC
    sequence could rewrite a terminal or hide output. Keep only printable
    characters so the value is inert.
    """
    return "".join(c for c in text if ord(c) >= 0x20 and not 0x7F <= ord(c) <= 0x9F)
