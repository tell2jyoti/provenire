# STATUS — where we are

> Single source of truth for "where did we leave off". Read this **first** on
> every resume (see `/resume`). The orchestrator (the `feature` skill / main
> agent) updates it; reviewers never write here.
> Convention + how to read it: `docs/dev-journal/README.md`.

## Now

- **Active feature:** **none — Phase 1 (F1–F9) COMPLETE.** F9 committed
  (`0f01be6`). No feature is mid-flight. Interim work since: **Phase-1 PR #4
  merged**, repo **rebranded** (attestable → provenire), README overhaul, and a
  standalone **`demo/`** (two-act "watch it break, then watch us catch it") built.
- **Loop step:** between phases. There is no F10 in the blueprint §09 backlog —
  next work is **Phase 2** (integration, not a single loop feature): see Next action.
- **Branch:** `docs/readme-overhaul` (README + rebrand + `demo/`). **Phase-1 PR
  [#4](https://github.com/tell2jyoti/provenire/pull/4) MERGED** (`6da807b`), F1–F9
  on `main`. `chore/agent-context-setup` retired.
- **Last red:** F9 collection ModuleNotFoundError (`evidence.bundle`) — fixed green. ·
  **Last green:** F9, **461 passed**, ruff + mypy strict clean.
- **Open findings:** none blocking. **Owner OQs** accumulating across F2–F5 logs
  (§Decisions): F2 — dedup wording, NFKC/homoglyph, non-Cc/Cf invisibles, size
  cap; F3 — schema finding_type taxonomy, seed breadth, schema-weakness evasion
  gaps, duplicate-name wording, false `normalize._schema` docstring claim; F4 —
  floor/gate defaults, scalar-score deferral, silent suppression; F5 — run-metadata
  injection point (F6/F7), schema_version bump policy, remediation/signed artifacts,
  JSON float repr cross-platform; F6 — live transport adapter deferred (C6 stub),
  output surface minimal, no private-target blocking (that's F7), --fail-on default.
- **Next action:** Phase 1 is done — **no more single-feature loops in the §09
  backlog.** Phase 2 is integration/wiring, each piece its own loop once specced:
  1. **End-to-end path** — assemble connect→scan→detect→score→**map (F8)**→
     **evidence (F9)**; today F6 CLI + F7 API stop at the report. Add an engine
     **`finding_type` taxonomy export** to source `evaluated_types` (mapping-pack
     OQ-1 / evidence OQ-3), then feed it through.
  2. **Live MCP transport adapter** — the F1/F6 `_default_connect` C6 stub; real
     stdio + streamable_http. Unblocks actual scans (F7 OQ-3 anti-rebinding too).
  3. **Persistence** — `report_url`/scan retrieval (F5/F7 deferred): Postgres/S3,
     `GET /scan/{id}`.
  4. **Signing + bundle packaging** — NFR-04 over F9's deterministic `.json`
     (evidence OQ-2).
  5. **Named-regulation packs** — HIPAA/SOC2 as new `packs/*.yaml` (data only; the
     mapping engine already loads them — architecture law delivering as designed).
  Recommend opening a **PR of `chore/agent-context-setup` → `main`** to land the
  whole F1–F9 phase first.
- **Design seam:** engine core is built against a `Session` Protocol (initialize /
  list_tools / list_resources / list_prompts); unit tests use an in-memory fake —
  no network, no `mcp` SDK (not installed). Real SDK adapter wired later.
- **Spec gate cleared:** `detection-rules-spec.md` §1/§2/§3.1 filled from the TDD
  (was a stub). Eyeball before trusting the tests.

_Last updated: 2026-07-06 — built `demo/` (two-act break→catch demo; consumer only,
no package change). PR #4 merged, repo rebranded, README overhauled. **PHASE 1
COMPLETE (F1–F9):** open-core scanner (F1–F6) + control plane (F7 scan API + SSRF,
F8 mapping engine + baseline pack, F9 evidence export). Next: Phase 2 integration
(end-to-end wiring, live transport, persistence, signing, regulation packs) — see
Next action._

## Phase-1 feature backlog (blueprint §09)

One feature = one trip through the loop, in order. Layer column: which package.
Each feature gets its own log file `F<n>-<slug>.md` (copy `_TEMPLATE.md`) once
started.

| # | Feature | First tests (red) | Layer | State |
| --- | --- | --- | --- | --- |
| F1 | Connect + enumerate | Handshake, list tools/resources/prompts, timeout, manifest hash | engine | ☑ done (`9ba2996`, 41 tests) |
| F2 | Poisoning detection | Hidden-directive, invisible-unicode, exfil patterns vs fixtures | engine | ☑ done (`2abd153`, 97 tests) |
| F3 | Over-privilege + schema | Shell/file/SQL flags, missing/unbounded schema | engine | ☑ done (`f1975c1`, 161 tests) |
| F4 | Scoring | Severity normalization, confidence, suppression | engine | ☑ done (`26b52a1`, 207 tests) |
| F5 | Report | JSON + HTML artifact shape, deterministic output | engine | ☑ done (`f855cde`, 248 tests) |
| F6 | CLI | stdio scan, exit codes, CI-fail threshold | cli | ☑ done (`060bcf4`, 288 tests) |
| F7 | Scan API + SSRF guard | POST /scan, blocked_target on metadata/RFC-1918, rate limit | control | ☑ done (`8e53fc5`, 364 tests) |
| F8 | Mapping engine + baseline pack | Loads baseline.yaml, finding_type→control, ControlState, pass & fail | control | ☑ done (`cfe8d0e`, 422 tests) |
| F9 | Evidence export | Pack-driven bundle, pack id/version recorded, deterministic output | control | ☑ done (`0f01be6`, 461 tests) |

F1–F6 = open core / free scanner. F7–F9 = control plane.

## Phase log (most recent first)

- **2026-07-06** — Built `demo/` (not a §09 feature; a consumer of the shipped
  packages, no engine/control_plane change). Two-act demo: Act 1 a compromised
  agent leaks a **decoy** secret to a **local mock sink** via a poisoned MCP tool
  description; Act 2 runs the **real** engine + control_plane over the identical
  server (in-memory `Session`) and flags `tool.poisoning` HIGH + `tool.exfiltration`
  CRITICAL, writing a deterministic `out/evidence.json`. Ships `--safe-mode`
  (no-LLM, reproducible) + a live LangGraph/stdio-MCP path (optional `[live]`
  extra). Signatures verified against source + `packages/*/tests/`; import boundary
  intact; ruff + mypy --strict clean on `demo/`; 461 package tests still green;
  `python demo/run_demo.py` self-checks (non-zero exit if Act 2 misses the poison).
  Prior interim work on this branch: PR #4 merge, attestable→provenire rebrand,
  README overhaul.
- **2026-07-04** — F9 (evidence export) committed (`0f01be6`, 461 tests) —
  **Phase 1 complete.** Pure, deterministic `build_evidence` assembles Manifest +
  ScanResult + F8 EvaluationResult into one self-contained JSON compliance record
  (records pack id/version; provenance injected verbatim; finding text faithful,
  not stripped). Reviews: security 0 findings, code MEDIUM (test type:ignore) fixed,
  qa PASS. Next: Phase 2 integration.
- **2026-07-04** — F8 (mapping engine + baseline pack) committed (`cfe8d0e`, 422
  tests). Second control-plane feature: data-only YAML pack (safe_load,
  fail-closed) maps framework-neutral finding_types → vendor-neutral controls;
  `evaluate_pack` → per-control ControlState with **honest N/A** (never a false
  pass for an unevaluated check); deterministic (tuples/sorted/pack-order). Ships
  `packs/baseline.yaml` (4 MCP-* controls, all 6 types). Review: security CRITICAL
  (wheel packaging) withdrawn after building the wheel; code HIGH (mutable list
  fields → tuples) fixed. Next: F9.
- **2026-07-04** — F7 (scan API + SSRF guard) committed (`8e53fc5`, 364 tests).
  First control-plane feature: `POST /scan` over the engine F1→F5 pipeline +
  routability-based SSRF guard (fails closed, before any socket) + per-IP rate
  limit (XFF trusted only behind a configured proxy, default off). Security HIGH
  (XFF spoof bypass) found + closed in review. Next: F8.
- **2026-06-28** — Set up agent context: pinned reference library
  (`docs/references/`, MCP 2025-06-18 security + authorization vendored), phase
  journal (`docs/dev-journal/`), wired the 4 review agents + `feature`/`resume`
  skills to read both. No production code. Next: F1.
- **2026-06-28** — Scaffold committed (`9ca9303`): repo structure + agent panel
  (architect, code-reviewer, security-reviewer, qa) + guardrails.
