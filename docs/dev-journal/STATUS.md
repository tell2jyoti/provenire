# STATUS — where we are

> Single source of truth for "where did we leave off". Read this **first** on
> every resume (see `/resume`). The orchestrator (the `feature` skill / main
> agent) updates it; reviewers never write here.
> Convention + how to read it: `docs/dev-journal/README.md`.

## Now

- **Active feature:** none — **F3 done** (`f1975c1`). Next: F4. Log: `F3-over-privilege-schema.md`.
- **Loop step:** F3 complete through step 7 (committed). Ready to start F4.
- **Branch:** `chore/agent-context-setup`.
- **Last red:** F3 import-error (detect_over_privilege) + non-string-key crash +
  SQL prose FP — all fixed green. · **Last green:** F3, **161 passed**, ruff + mypy strict clean.
- **Open findings:** none blocking. **Owner OQs** accumulating across F2/F3 logs
  (§Decisions): F2 — dedup wording, NFKC/homoglyph, non-Cc/Cf invisibles, size
  cap; F3 — schema finding_type taxonomy, seed breadth, schema-weakness evasion
  gaps, duplicate-name wording, false `normalize._schema` docstring claim.
- **Next action:** Start **F4 (scoring)** via `/feature F4`; needs spec §4 filled
  first (currently a stub) — severity normalization, confidence, suppression.
- **Design seam:** engine core is built against a `Session` Protocol (initialize /
  list_tools / list_resources / list_prompts); unit tests use an in-memory fake —
  no network, no `mcp` SDK (not installed). Real SDK adapter wired later.
- **Spec gate cleared:** `detection-rules-spec.md` §1/§2/§3.1 filled from the TDD
  (was a stub). Eyeball before trusting the tests.

_Last updated: 2026-06-28 — F3 committed (`f1975c1`, 161 tests). Next: F4._

## Phase-1 feature backlog (blueprint §09)

One feature = one trip through the loop, in order. Layer column: which package.
Each feature gets its own log file `F<n>-<slug>.md` (copy `_TEMPLATE.md`) once
started.

| # | Feature | First tests (red) | Layer | State |
| --- | --- | --- | --- | --- |
| F1 | Connect + enumerate | Handshake, list tools/resources/prompts, timeout, manifest hash | engine | ☑ done (`9ba2996`, 41 tests) |
| F2 | Poisoning detection | Hidden-directive, invisible-unicode, exfil patterns vs fixtures | engine | ☑ done (`2abd153`, 97 tests) |
| F3 | Over-privilege + schema | Shell/file/SQL flags, missing/unbounded schema | engine | ☑ done (`f1975c1`, 161 tests) |
| F4 | Scoring | Severity normalization, confidence, suppression | engine | ☐ not started |
| F5 | Report | JSON + HTML artifact shape, deterministic output | engine | ☐ not started |
| F6 | CLI | stdio scan, exit codes, CI-fail threshold | cli | ☐ not started |
| F7 | Scan API + SSRF guard | POST /scan, blocked_target on metadata/RFC-1918, rate limit | control | ☐ not started |
| F8 | Mapping engine + baseline pack | Loads baseline.yaml, finding_type→control, ControlState, pass & fail | control | ☐ not started |
| F9 | Evidence export | Pack-driven bundle, pack id/version recorded, deterministic output | control | ☐ not started |

F1–F6 = open core / free scanner. F7–F9 = control plane.

## Phase log (most recent first)

- **2026-06-28** — Set up agent context: pinned reference library
  (`docs/references/`, MCP 2025-06-18 security + authorization vendored), phase
  journal (`docs/dev-journal/`), wired the 4 review agents + `feature`/`resume`
  skills to read both. No production code. Next: F1.
- **2026-06-28** — Scaffold committed (`9ca9303`): repo structure + agent panel
  (architect, code-reviewer, security-reviewer, qa) + guardrails.
