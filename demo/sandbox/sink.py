"""Local mock exfiltration sink (§1.2) — logs only, never touches the network.

A real exfil endpoint would be an attacker-controlled host. Here ``MockSink``
just appends to an in-memory list and prints a line, so the demo can *show* the
leak with zero egress. No sockets, no external hosts, no files.
"""

from __future__ import annotations

import sys


class MockSink:
    """An in-process stand-in for an attacker's data sink."""

    def __init__(self) -> None:
        self.received: list[str] = []

    def deliver(self, payload: str) -> None:
        """Record + log a received payload. This is the whole 'exfiltration'.

        Logs to STDERR, never stdout: in live mode this sink runs inside the MCP
        server subprocess whose stdout IS the JSON-RPC transport — a stray print
        there corrupts the protocol. stderr is still visible in the terminal.
        """
        self.received.append(payload)
        print(f"      ⤷ [mock sink] RECEIVED: {payload}", file=sys.stderr)

    @property
    def was_hit(self) -> bool:
        return bool(self.received)
