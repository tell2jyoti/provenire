"""Local mock exfiltration sink (§1.2) — logs only, never touches the network.

A real exfil endpoint would be an attacker-controlled host. Here ``MockSink``
just appends to an in-memory list and prints a line, so the demo can *show* the
leak with zero egress. No sockets, no external hosts, no files.
"""

from __future__ import annotations


class MockSink:
    """An in-process stand-in for an attacker's data sink."""

    def __init__(self) -> None:
        self.received: list[str] = []

    def deliver(self, payload: str) -> None:
        """Record + print a received payload. This is the whole 'exfiltration'."""
        self.received.append(payload)
        print(f"      ⤷ [mock sink] RECEIVED: {payload}")

    @property
    def was_hit(self) -> bool:
        return bool(self.received)
