"""The single public engine entrypoint the CLI (F6) calls.

Orchestrates the F1 pipeline: handshake -> collect -> normalize -> manifest.
Emits a `Manifest` and no `Finding`s (detection begins at §3.2).
"""

from __future__ import annotations

from .connect.handshake import handshake
from .connect.session import Session, Transport
from .enumerate.collect import collect
from .enumerate.manifest import Manifest, build_manifest
from .enumerate.normalize import to_prompt_record, to_resource_record, to_tool_record


async def scan(session: Session, *, transport: Transport, timeout: float = 10.0) -> Manifest:
    await handshake(session, timeout=timeout)
    raw_tools, raw_resources, raw_prompts = await collect(session, timeout=timeout)
    return build_manifest(
        [to_tool_record(t) for t in raw_tools],
        [to_resource_record(r) for r in raw_resources],
        [to_prompt_record(p) for p in raw_prompts],
        transport=transport,
    )
