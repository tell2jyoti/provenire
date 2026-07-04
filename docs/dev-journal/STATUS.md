# STATUS — where we are

> Single source of truth for "where did we leave off". Read this **first** on
> every resume (see `/resume`). The orchestrator (the `feature` skill / main
> agent) updates it; reviewers never write here.
> Convention + how to read it: `docs/dev-journal/README.md`.

## Now

- **Active feature:** **none** — F8 committed (`cfe8d0e`). Next: **F9 (Evidence
  export)** — the last Phase-1 feature. Log to open: copy `_TEMPLATE.md` →
  `F9-evidence-export.md`.
- **Loop step:** between features — start F9 via `/feature F9`.
- **Branch:** `chore/agent-context-setup`.
- **Last red:** F8 collection ModuleNotFoundError (`mapping.evaluate`) — fixed green. ·
  **Last green:** F8, **422 passed**, ruff + mypy strict clean.
- **Open findings:** none blocking. **Owner OQs** accumulating across F2–F5 logs
  (§Decisions): F2 — dedup wording, NFKC/homoglyph, non-Cc/Cf invisibles, size
  cap; F3 — schema finding_type taxonomy, seed breadth, schema-weakness evasion
  gaps, duplicate-name wording, false `normalize._schema` docstring claim; F4 —
  floor/gate defaults, scalar-score deferral, silent suppression; F5 — run-metadata
  injection point (F6/F7), schema_version bump policy, remediation/signed artifacts,
  JSON float repr cross-platform; F6 — live transport adapter deferred (C6 stub),
  output surface minimal, no private-target blocking (that's F7), --fail-on default.
- **Next action:** Start **F9 (Evidence export)** via `/feature F9` — the **final
  Phase-1 feature**. Backlog: pack-driven bundle, pack id/version recorded,
  deterministic output. Spec is a stub (`docs/evidence-export-spec.md` doesn't
  exist yet) → same kickoff as F7/F8: distill a spec (owner approves) before tests.
  Builds directly on F8: consumes `EvaluationResult` (`PackRef` + per-control
  states) → an evidence bundle. **Carry-overs to resolve here:** OQ-1 wire
  `evaluated_types` from a real engine taxonomy export (mapping-pack-spec §7); the
  scan→map→evidence path gets assembled; F5/F7 deferred run-metadata + signed-
  artifact + `report_url` persistence questions likely resurface. Named-regulation
  packs (HIPAA/SOC2) are post-Phase-1.
- **Design seam:** engine core is built against a `Session` Protocol (initialize /
  list_tools / list_resources / list_prompts); unit tests use an in-memory fake —
  no network, no `mcp` SDK (not installed). Real SDK adapter wired later.
- **Spec gate cleared:** `detection-rules-spec.md` §1/§2/§3.1 filled from the TDD
  (was a stub). Eyeball before trusting the tests.

_Last updated: 2026-07-04 — F8 committed (`cfe8d0e`, 422 tests). **F1–F6 (open core
/ free scanner) + F7 (scan API + SSRF guard) + F8 (mapping engine + baseline pack)
done.** Next: F9 (evidence export) — the last Phase-1 feature._

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
| F9 | Evidence export | Pack-driven bundle, pack id/version recorded, deterministic output | control | ☐ not started |

F1–F6 = open core / free scanner. F7–F9 = control plane.

## Phase log (most recent first)

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
