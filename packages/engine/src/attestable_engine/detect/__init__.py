"""Detection rules (§3.2 onward) — emit Findings over a normalized Manifest."""

from __future__ import annotations

from .poisoning import detect_poisoning

__all__ = ["detect_poisoning"]
