# F6 — CLI

> The durable record of *why*, not just *what*. Reviewers are read-only — their
> findings are pasted here by the orchestrator.

- **Layer:** cli (`packages/cli` — first feature outside `packages/engine`)
- **Branch:** `chore/agent-context-setup`
- **Spec source:** docs/cli-spec.md §1–§2 (C0–C6) — **new spec doc** (CLI isn't
  detection-rules or packs). Derived from TDD §03/§07/§10, PRD FR-05 + FR-13,
  Blueprint §09 F6. Wires the F1→F5 engine pipeline.
- **Started:** 2026-07-01 · **Done:** 2026-07-01 (`060bcf4`)

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (ModuleNotFoundError at collection)
- [x] 3. Minimum code → **GREEN** (278 passed)
- [x] 4. Refactor; tests stay green (single-parse via ScanResult)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. All findings fixed test-first (5 security incl. 2 HIGH, code blocking, 4 qa);
      **all three re-reviewed clean** — security clean, code clean, qa PASS
      (288 passed, ruff + mypy --strict clean)
- [x] 7. Human read the diff → committed (`060bcf4`)

## 1. Architect design
_Ordered test list (each derived from a spec rule — cite it). Modules/data flow.
Acceptance criteria. Spec gaps flagged + stopped on._

**Spec gate cleared first.** No CLI spec existed; authored `docs/cli-spec.md`
(C0–C6) from the source docs + owner decisions (this session):
- **Transport scope:** CLI-now with the live connector **injected/deferred** — F6
  builds & unit-tests everything from a connected `Session` onward (fake Session,
  no network/SDK, `asyncio.run` like the engine tests); the real stdio adapter is
  a later integration slice (C6 stub → exit 3).
- **Exit codes (C3):** distinct — `0` pass · `1` gate fail · `2` usage/args ·
  `3` target unreachable.

**Module/data flow (architect).** New `attestable_cli/cli.py`: `run_scan(target,
*, fail_on="high", timeout=10.0, transport="stdio", json_out=False,
output_dir=None, connect=_default_connect) -> int` (sync; `asyncio.run` bridges to
the async engine) + `main(argv=None) -> int` (stdlib argparse) + `_default_connect`
(C6 stub → TargetUnreachable). Console script `attestable = cli:_console`
(`raise SystemExit(main())`) added to `packages/cli/pyproject.toml`. Pipeline:
connect → scan → detect_poisoning+detect_over_privilege → score_findings(
gate_threshold=fail_on) → build_report. Imports only `attestable_engine` (no
control_plane).

**Ordered test list (~32; each cites C0–C6; +/-).** `tests/test_cli.py`, local
fake `connect`/Session (no cross-package conftest, no network/SDK):
- C1 args: defaults (fail_on=high, timeout=10, transport=stdio, json=False,
  output=None); all flags parse; bad `--fail-on` choice / unknown flag / missing
  target → **exit 2** (argparse).
- C2 pipeline (behavioral): a poisoned tool → finding surfaces in output; empty
  server → no findings; timeout flows through.
- C3 exit codes: gate pass → **0**; gate fail → **1**; injected connect raises
  TargetUnreachable → **3** with message on **stderr not stdout**.
- C1→C3 threshold: high finding → fail with default, **pass** with
  `--fail-on critical`, fail with `--fail-on medium`.
- C4 output: default human summary (gate/counts/worst/finding lines, risk order,
  no JSON); `--json` → only valid JSON == report.json, no summary text; `--output
  DIR` → writes report.json+report.html (creates dir), prints paths (stdout in
  default mode, **stderr** in `--json` mode).
- C0 no side effects: no `--output` → **no files**; error exit → no files;
  determinism (same inputs → same stdout+code); no global-state bleed across calls.
- C6: `_default_connect` raises TargetUnreachable; message flags the deferred
  adapter.

**Refinements over architect list (my calls, logged):** replaced "was function X
called" spy tests with **behavioral** assertions (exit code + stdout content prove
the pipeline ran); pinned a concrete human-summary format and assert key
substrings (spec was silent); local fake instead of importing the engine conftest.

**Acceptance:** all green; C1–C6 pos+neg; exit codes 0/1/2/3; `--fail-on`→F4;
output modes correct; no files without `--output`; no `control_plane` import;
console script wired; ruff + mypy --strict clean; no network/SDK/pytest-asyncio.
**Spec gaps:** human-summary wording (pinned by tests); `--json --output` path→
stderr (confirmed C4); C5 no-egress has no unit negative (architectural — noted).

## 2. Red proof

~32 tests written before `attestable_cli/cli.py` existed; collected RED on the
missing module:

```
ImportError while importing test module '.../packages/cli/tests/test_cli.py'.
E   ModuleNotFoundError: No module named 'attestable_cli.cli'
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
```

## 3 + 4. Green & refactor

Implemented `packages/cli/src/attestable_cli/cli.py`:
- `run_scan(...) -> int` (sync; `asyncio.run` bridges the async engine) — connect
  (injected) → `scan` → `detect_poisoning`+`detect_over_privilege` →
  `score_findings(gate_threshold=fail_on)` → `build_report`; maps gate/errors to
  exit codes `EXIT_PASS/GATE_FAIL/UNREACHABLE` (0/1/3); usage=2 via argparse.
- `_emit`/`_summary`/`_write_artifacts` — C4 output modes: human summary (gate/
  counts/worst + one tab-line per finding in F4 order) vs `--json` (report JSON
  only); `--output DIR` writes report.json+report.html (mkdir -p), paths to stdout
  (default) or stderr (`--json`, keeping stdout pure JSON).
- `_parser` — stdlib argparse, `scan` subcommand + `--fail-on/--timeout/
  --transport/--json/--output`; `main(argv, *, connect=_default_connect)`.
- `_default_connect` — C6 stub raising `TargetUnreachable` (deferred adapter).
- Console script `attestable = attestable_cli.cli:_console` wired in cli pyproject.
- Imports only `attestable_engine` (no control_plane).

Verified the real console script: `attestable scan srv` → exit 3 + clear message;
`attestable scan` (no target) → exit 2 usage; `--help` lists all options.

Final run: **278 passed** (engine 248 + cli 30). ruff + mypy --strict clean (34 files).
Refactor: hoisted `json`/`sys` imports to module top; dropped an unused
`type: ignore` (FakeSession structurally satisfies the `Session` Protocol).

## 5 + 6. Review findings

Round 1 — all three ran on the green diff (278). security **5 findings**
(2 HIGH), code **1 blocking + 2**, qa **FAIL (4 gaps)**. All fixed test-first
(287 passed); spec gained exit code **4**.

### security-reviewer — 5 findings, all addressed
- **HIGH — terminal injection (FIXED):** the human summary printed hostile
  `entity_ref`/`rationale` raw; a server could embed `\x1b[2J` to clear the screen
  and hide findings. Added `_safe()` stripping C0/C1 control bytes (incl. ESC) from
  interpolated finding text; test `test_c4_summary_sanitizes_terminal_control_chars`
  (raw ESC RED→green). JSON/`--output` paths already control-safe (json.dumps / F5
  escape).
- **HIGH — exit-code ambiguity (FIXED):** only `TargetUnreachable` was caught; any
  other engine error crashed with Python's exit `1`, colliding with gate-fail.
  Added `EXIT_ERROR=4` + broad `except Exception` (spec C3 updated); test
  `test_c3_unexpected_engine_error_exits_4_not_1` (RED→green).
- **MEDIUM — `--output` FS errors (FIXED):** `mkdir`/`write_text` could raise
  (permission / path is a file) → traceback. Wrapped `_emit` write in
  `except OSError → exit 4`; test `test_c3_output_write_error_exits_4` (RED→green).
- **MEDIUM — stub echoes `{target}` (FIXED):** target (a possible secret-bearing
  stdio command) removed from `_default_connect` message; test
  `test_c6_stub_message_excludes_target` (RED→green).
- **LOW — `_gate` JSON re-parse (FIXED via refactor):** gate now read from
  `result.score.gate` (no JSON round-trip). Open-core boundary / no-egress / SSRF
  scope all confirmed **clean**.

### code-reviewer — 1 blocking + 2, all FIXED
- **BLOCKING — double-parse of `report.json`** (`_gate` + `_summary`): refactored
  `_scan` to return `(report, result)`; `_summary` builds from the `ScanResult`
  dataclasses (zero `json.loads` in the CLI now — `import json` dropped).
- **Non-blocking — forward-ref quotes** on `Transport` in the `Connect` alias:
  removed. **Nit — redundant `str()`** in `_gate`: gone with the refactor.

### qa — verdict **FAIL (4 gaps) → all filled → (re-audit pending)**
- **FAIL-1:** no `--fail-on low` test → `test_c1_fail_on_low_parses_and_gates`
  (low finding fails at low, passes at default high).
- **FAIL-2/3:** exit code not asserted independent of output mode →
  `test_c3_exit_code_independent_of_json_mode` (parametrized) +
  `test_c3_exit_code_independent_of_output_mode`.
- **FAIL-4:** no empty-findings `--json` test →
  `test_c4_json_mode_empty_findings_valid_json`.
  (These coverage tests were green on arrival — recorded honestly.)

**Round 2 — all three clean.** security **security-clean, zero remaining** (verified
`_safe` conservative+correct; `except Exception` doesn't mask `BaseException`; gate
can't be flipped; `--json` stdout pure). code **clean, no remaining issues**
(double-parse gone, refactor reads cleanly, exception order correct). qa **PASS**
with one cosmetic note (combined `--json`+`--output` exit code) → closed with
`test_c4_output_dir_json_mode_gate_fail_exits_1` + an assert on the pass case
(288 passed). Definition of done met; awaiting human diff read.

## Decisions & open questions

**OQ — owner decisions carried from cli-spec (not invented here):**
1. Live stdio/streamable_http transport adapter is **deferred** (C6 stub); real
   connect + integration fixtures land with the transport slice (needs `mcp`).
2. Output surface (default human summary / `--json` / `--output DIR`) is minimal;
   richer TTY formatting/colour is a later increment.
3. CLI does **not** block private/RFC-1918 targets (that's hosted F7); the CLI is
   the sanctioned no-egress path for exactly those (FR-05).
4. `--fail-on` default `high` mirrors F4's `gate_threshold` default; owner may
   retune the CI breach line.

## Commit

`060bcf4` — feat(cli): F6 attestable scan — F1→F5 pipeline, exit codes,
--fail-on/--json/--output. Owner approved the diff; 6 files, 288 tests green.
First feature outside `packages/engine`; new `docs/cli-spec.md`.
