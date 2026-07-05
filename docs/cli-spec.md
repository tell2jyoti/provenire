# CLI Spec

> The contract for the `provenire` command-line tool (feature F6, layer: cli).
> This document is the source of the CLI's tests — every CLI test cites a rule id
> here. Derived from TDD §03 (CLI is the only path for stdio & private servers),
> §07 (engine pipeline), §10 (report artifacts); PRD FR-05 (local / no-egress),
> FR-13 (CI exit codes); Blueprint §09 (F6 row: "stdio scan, exit codes, CI-fail
> threshold") + `run: uv run provenire scan <url>`.
>
> **Layering.** The CLI lives in `packages/cli` (Apache-2.0, open). It imports the
> engine's public API (`provenire_engine`) and **nothing from `control_plane`**
> (CLAUDE.md). It emits the engine's framework-neutral findings verbatim — it
> **never** names a regulation.
>
> Status: §1–§2 filled (F6).

## 1. Purpose & scope

`provenire scan <target>` connects to a live MCP server, runs the engine
pipeline (F1→F5: enumerate → detect → score → report) and exits with a
CI-meaningful code. The CLI is the **sanctioned path for stdio and private /
no-egress servers** (TDD §03, PRD FR-05): it runs the full scan locally and never
transmits the manifest off-host. (The hosted portal, F7, scans public servers
only and rejects stdio — not this layer.)

**Transport seam (Phase-1 boundary).** The engine drives scans through a
`Session` Protocol; the real MCP SDK adapter (stdio subprocess / streamable_http,
camelCase `inputSchema` mapping) is a **later integration slice** and the `mcp`
SDK is not a Phase-1 dependency (`connect/session.py`). F6 therefore builds the
CLI **orchestration, argument, exit-code and output** contract against an
**injected connection factory**: unit tests supply an in-memory fake `Session`
(no network, no SDK), exactly as the engine's own unit tests do
(`asyncio.run(scan(fake, ...))`). The live connector is stubbed pending the
transport slice (§2 C6). What F6 delivers and proves is everything from a
connected `Session` onward, plus the CLI surface around it.

## 2. The contract

The public, unit-testable surface:

- `run_scan(target, *, fail_on="high", timeout=10.0, transport="stdio",
  json_out=False, output_dir=None, connect=_default_connect) -> int` — a **sync**
  function (internally `asyncio.run`) returning the process exit code. It prints
  to `sys.stdout` / `sys.stderr` (tests capture via `capsys`) and does **not**
  call `sys.exit`. `connect` is an injectable
  `Callable[[str, Transport, float], Awaitable[Session]]`.
- `main(argv: list[str] | None = None, *, connect=_default_connect) -> int` —
  parses args (stdlib `argparse`, no third-party CLI dep) and dispatches to
  `run_scan`, forwarding `connect`. The `connect` keyword is the injection seam
  (tests pass a fake; the real adapter is wired here later); it defaults to the
  C6 stub so the public `main(argv)` call is unchanged. The console entry point
  `provenire` is `raise SystemExit(main())` (added to
  `packages/cli/pyproject.toml` `[project.scripts]`).

### 2.1 Rules

- **C1 — Command & arguments.** `provenire scan <target>` with options:
  - `--fail-on {critical,high,medium,low}` (default **`high`**) → passed to F4
    `score_findings(gate_threshold=...)`; sets the CI breach line.
  - `--timeout SECONDS` (float, default **`10.0`**) → engine R2 timeout.
  - `--transport {stdio,streamable_http}` (default **`stdio`**) → the CLI default
    is stdio (its reason to exist); the value is recorded in the report.
  - `--json` → machine-output mode (C4).
  - `--output DIR` → also write artifacts to disk (C4).
  Unknown args / bad choices are usage errors (C3 code 2, argparse default).

- **C2 — Pipeline orchestration.** From a connected `Session`, `run_scan`:
  1. `manifest = await scan(session, transport=transport, timeout=timeout)` (F1);
  2. `findings = detect_poisoning(manifest) + detect_over_privilege(manifest)`
     (F2+F3 — order irrelevant; scoring re-orders deterministically);
  3. `result = score_findings(findings, gate_threshold=fail_on)` (F4);
  4. `report = build_report(manifest, result)` (F5).
  Deterministic: the same server + args yield the same output and exit code.

- **C3 — Exit codes (the FR-13 CI contract).**
  - **`0`** — scan completed, **gate `pass`** (no finding at/above `--fail-on`).
  - **`1`** — scan completed, **gate `fail`** (≥ `--fail-on`) — the CI breach.
  - **`2`** — **usage / argument error** (argparse: unknown flag, bad choice,
    missing target). argparse prints usage to stderr and exits 2.
  - **`3`** — **target unreachable** — the engine raised `TargetUnreachable`
    (timeout / refused / DNS / reset, engine R2). Printed to stderr, not stdout.
  - **`4`** — **scan/output error** — any *other* failure (an unexpected engine
    exception during the scan, or an `OSError` writing `--output` artifacts). The
    CLI catches it, prints `error: …` to **stderr** (never a raw traceback), and
    exits 4 — so a crash is **never** mistaken for a gate breach (`1`). Only
    `KeyboardInterrupt`/`SystemExit` propagate.
  Exit code is a function of the gate (C3) **independent of output mode** (C4).

- **C4 — Output modes.** stdout format is chosen by `--json`; `--output` is
  additive:
  - **default** (no `--json`): a human-readable summary to **stdout** — gate,
    worst severity, per-severity counts, and one line per finding
    (`severity  finding_type  entity_ref  — rationale`), in F4 risk order.
  - **`--json`**: the report's machine **JSON** (F5 `report.json`) is written to
    stdout and **nothing else** on stdout (pipeable); no human summary.
  - **`--output DIR`**: additionally writes `DIR/report.json` and
    `DIR/report.html` (F5 artifacts) and prints the written paths (to stdout in
    default mode, to stderr in `--json` mode so stdout stays pure JSON). Creating
    `DIR` if absent.
  All findings/rationale printed to a terminal are the engine's text; the CLI does
  not render HTML to stdout (that is the `--output` file).

- **C5 — No-egress / stdio (FR-05, TDD §03).** The CLI accepts `stdio` (its
  sanctioned path) and performs **no network egress of the manifest** — it only
  prints locally and writes to `--output` on the local filesystem. It does **not**
  block private / RFC-1918 / link-local targets: that guard is a hosted
  request-layer concern (F7), and the CLI is precisely the path such targets are
  meant to use.

- **C6 — Deferred live connector.** `_default_connect` is a Phase-1 **stub**: it
  raises `TargetUnreachable` with a message that the transport adapter is not yet
  wired (so `provenire scan x` today exits **3** with a clear reason, not a
  stack trace). The real stdio/streamable_http adapter lands with the transport
  slice and is covered by integration fixtures; unit tests inject their own
  `connect`. This is the one contract F6 stubs rather than implements.

- **C0 — No unexpected side effects.** With no `--output`, `run_scan` writes no
  files. It never mutates global state, and (given the same injected `Session`
  and args) is deterministic in stdout + exit code. Errors go to stderr; only the
  chosen artifact (summary or JSON) goes to stdout.

Acceptance (F6): given an injected `connect` returning an in-memory `Session`,
`run_scan` / `main` orchestrate the F1→F5 pipeline and return the correct exit
code per C3 for pass / fail / unreachable, honor `--fail-on` (C1→F4), emit the
correct stdout for each output mode (C4), write artifacts under `--output` (C4),
and produce **no files** otherwise (C0); usage errors exit 2 (C3); the deferred
connector exits 3 (C6). Every rule C1–C6 has positive and negative tests; no
network, no `mcp` SDK, no `control_plane` import.

## 3. Test fixtures

Unit tests reuse the engine's in-memory `FakeSession` pattern (an object exposing
`initialize` / `list_tools` / `list_resources` / `list_prompts`) via an injected
`connect`, plus `capsys` (stdout/stderr) and `tmp_path` (`--output`). No network,
no subprocess, no SDK. The real transport adapter's integration tests (marked
`slow`) arrive with that slice.
