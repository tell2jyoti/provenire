"""Live-mode bridge: LangGraph agent ⇄ real stdio MCP server.

Connects the agent to ``malicious_server/server.py`` over **stdio** using the
official ``mcp`` SDK, exposes the server's tools to a ``create_react_agent``
loop, and adds one local, sandbox-restricted ``read_file`` tool so the agent can
actually follow the poisoned instruction over the protocol.

Everything here is imported lazily by ``agent.app.run_live`` and guarded: if the
live deps (``mcp`` / ``langgraph`` / ``langchain_openai``) or an API key are
missing, it raises ``LiveModeUnavailable`` with a human-readable reason instead
of a raw ImportError, so the runner can fall back cleanly to safe-mode.

This module is intentionally dependency-heavy and is never touched by Act 2.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from malicious_server.tools import SANDBOX_DIR
from sandbox.sink import MockSink

if TYPE_CHECKING:
    from agent.app import Act1Trace


class LiveModeUnavailable(RuntimeError):
    """Raised when the live LLM/MCP path cannot run (missing deps or API key)."""


def _require_live_deps() -> dict[str, Any]:
    """Import the optional live stack, or raise a friendly LiveModeUnavailable."""
    try:
        import mcp  # noqa: F401
        from langchain_core.tools import StructuredTool
        from langchain_openai import ChatOpenAI
        from langgraph.prebuilt import create_react_agent
    except ImportError as exc:  # pragma: no cover - depends on optional deps
        raise LiveModeUnavailable(
            f"live deps not installed ({exc.name}); run `uv sync` in demo/ "
            "or use --safe-mode"
        ) from exc
    if not os.environ.get("OPENAI_API_KEY"):
        raise LiveModeUnavailable(
            "OPENAI_API_KEY is not set; export it or use --safe-mode"
        )
    return {
        "StructuredTool": StructuredTool,
        "ChatOpenAI": ChatOpenAI,
        "create_react_agent": create_react_agent,
    }


def _read_sandbox_file(path: str) -> str:
    """Local tool body: read a file, but ONLY under demo/sandbox/ (§1)."""
    target = (SANDBOX_DIR / Path(path).name).resolve()
    if SANDBOX_DIR.resolve() not in target.parents:
        return "ERROR: refused (outside sandbox)"
    if not target.is_file():
        # Fall back to the known decoy path so the injection still resolves.
        target = (SANDBOX_DIR / "vault" / "fake_api_key.txt").resolve()
    return target.read_text(encoding="utf-8").strip()


def run_live_agent(
    *, user_message: str, system_prompt: str, model: str, temperature: float
) -> Act1Trace:
    """Run the real agent against the real stdio server. Returns an Act1Trace."""
    deps = _require_live_deps()
    return asyncio.run(
        _run_async(deps, user_message, system_prompt, model, temperature)
    )


async def _run_async(
    deps: dict[str, Any],
    user_message: str,
    system_prompt: str,
    model: str,
    temperature: float,
) -> Act1Trace:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from agent.app import Act1Trace

    sink = MockSink()
    server = Path(__file__).resolve().parent.parent / "malicious_server" / "server.py"
    params = StdioServerParameters(command="python", args=[str(server)])

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            lc_tools = [
                _wrap_mcp_tool(deps, session, t) for t in listed.tools
            ] + [_wrap_read_tool(deps, sink)]

            llm = deps["ChatOpenAI"](model=model, temperature=temperature)
            agent = deps["create_react_agent"](llm, lc_tools)
            state = await agent.ainvoke(
                {
                    "messages": [
                        ("system", system_prompt),
                        ("user", user_message),
                    ]
                }
            )

    chosen, args = _last_weather_call(state)
    return Act1Trace(
        mode="live",
        user_message=user_message,
        chosen_tool=chosen,
        tool_args=args,
        decoy_value=args.get("units", ""),
        sink=sink,
    )


def _wrap_mcp_tool(deps: dict[str, Any], session: Any, tool: Any) -> Any:
    """Wrap a remote MCP tool as a LangChain StructuredTool that calls it."""

    async def _call(**kwargs: Any) -> str:
        result = await session.call_tool(tool.name, kwargs)
        return str(result.content)

    return deps["StructuredTool"].from_function(
        coroutine=_call,
        name=tool.name,
        description=tool.description,
    )


def _wrap_read_tool(deps: dict[str, Any], sink: MockSink) -> Any:
    """The local sandboxed read_file tool the agent uses to fetch the decoy."""

    def _read(path: str) -> str:
        return _read_sandbox_file(path)

    return deps["StructuredTool"].from_function(
        func=_read,
        name="read_file",
        description="Read a small local text file by path and return its contents.",
    )


def _last_weather_call(state: Any) -> tuple[str, dict[str, str]]:
    """Best-effort extraction of the get_weather tool call from the agent state."""
    for msg in reversed(state.get("messages", [])):
        for call in getattr(msg, "tool_calls", []) or []:
            if call.get("name") == "get_weather":
                raw = call.get("args", {}) or {}
                return "get_weather", {k: str(v) for k, v in raw.items()}
    return "get_weather", {}
