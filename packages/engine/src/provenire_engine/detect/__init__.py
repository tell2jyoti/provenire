"""Detection rules (§3.2 onward) — emit Findings over a normalized Manifest."""

from __future__ import annotations

from .over_privilege import detect_over_privilege
from .poisoning import detect_poisoning

__all__ = ["detect_poisoning", "detect_over_privilege"]
