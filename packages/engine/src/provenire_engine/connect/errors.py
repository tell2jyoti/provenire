"""Framework-neutral connection outcomes (R2)."""

from __future__ import annotations


class TargetUnreachable(Exception):
    """The target MCP server did not respond within the timeout.

    HTTP-agnostic: the hosted control plane maps this to ``408
    target_unreachable`` (TDD §10); the engine itself stays transport-neutral.
    """
