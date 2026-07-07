# Provenire demo — "watch it break, then watch us catch it"

A self-contained, two-act demo of MCP tool poisoning and how Provenire catches it.
Both acts run against the **same** malicious MCP server, defined once in
[`malicious_server/tools.py`](malicious_server/tools.py).

- **Act 1 — without Provenire.** A small agent connects to a malicious MCP
  server, reads a **poisoned tool description**, and is tricked into reading a
  **decoy secret** and handing it to a **local mock sink**. The harm is printed
  plainly.
- **Act 2 — with Provenire.** The identical server's tool definitions are fed
  through Provenire's real engine + control-plane pipeline, which flags the exact
  tool that leaked in Act 1 (`tool.poisoning` · HIGH) plus an exfiltration
  affordance (`tool.exfiltration` · CRITICAL), and writes a real evidence record.

The gap between the two acts is the whole pitch.

## What it proves

The scan would have caught the poisoned tool **before the agent ever connected**.
A static findings report tells you a tool is risky; this shows you the harm that
risk becomes, then shows the same scan flagging it. Act 2 also emits
`out/evidence.json` — a real, deterministic compliance record (pack id + version,
per-control pass/fail, the findings), the kind of artifact you'd hand an auditor.

## Run it

The demo is its **own** project (it consumes `provenire-engine` +
`provenire-control-plane` as a library and never modifies them). From this
`demo/` directory:

```bash
# Reproducible path — no LLM, no network. Best for CI and recording.
uv sync
uv run python run_demo.py --safe-mode
```

```bash
# Authentic path — a real LangGraph agent + real stdio MCP server.
uv sync --extra live
export OPENAI_API_KEY=...        # read from env at runtime; never logged
uv run python run_demo.py
```

Flags: `--safe-mode` (deterministic, stub agent), `--act 1|2` (one act only),
`--json` (machine-readable output). The runner exits non-zero if Act 2 fails to
flag the poisoned tool, so it doubles as a self-check.

> **Recording tip.** Live LLM obedience is probabilistic. Run the **live** path a
> few times and **record** the take where the break fires cleanly — that's the
> money shot. Use `--safe-mode` for CI and for reproducing the break on demand
> without an API call. Both are authentic in *mechanism*; safe-mode is just
> deterministic in *outcome*.

## Safety (this demonstrates a mechanism, not an attack tool)

- The "secret" is an obvious **decoy**:
  `sandbox/vault/fake_api_key.txt` = `SK-FAKE-DEMO-DO-NOT-USE-not-a-real-key`.
- "Exfiltration" is a **local mock sink** ([`sandbox/sink.py`](sandbox/sink.py))
  that only logs what it received. **No network egress, no external hosts.**
- Everything reads/writes only under `demo/sandbox/`; file access is
  path-guarded to that directory. No real files, `~/.ssh`, env vars, or
  credentials are ever touched.
- The LLM API key (live mode only) comes from the environment and is never logged.

## Layout

```
malicious_server/tools.py   single source of truth for the 3 tools
malicious_server/server.py  real FastMCP stdio server (Act 1, live)
agent/app.py                Act 1: safe-mode stub + live LangGraph agent
agent/mcp_client.py         live bridge: agent ⇄ stdio MCP server
provenire_check/            Act 2: in-memory Session → real engine + control_plane
sandbox/                    decoy vault + local mock sink
run_demo.py                 the one-command runner
out/                        generated report.json / evidence.json (gitignored)
```
