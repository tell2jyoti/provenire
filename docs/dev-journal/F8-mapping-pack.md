# F8 — Mapping engine + baseline pack

> Durable record of *why*, not just *what*. Reviewers are read-only — the
> orchestrator pastes their findings here.

- **Layer:** control (second `control_plane` / COMMERCIAL feature)
- **Branch:** `chore/agent-context-setup` (F1–F7 all landed here)
- **Spec source:** `docs/mapping-pack-spec.md` (distilled here — was a stub)
- **Started:** 2026-07-04 · **Done:** —

## Kickoff decisions (owner, 2026-07-04)

Asked before writing the spec because they change what gets built (spec was a
stub; the TDD it would distill from is not in-repo):

1. **Spec source:** owner chose *"I distill, you approve"* — I write
   `mapping-pack-spec.md` mapping the 6 engine `finding_type`s to a vendor-neutral
   MCP-security control set (grounded in the detection-rules-spec / pinned MCP
   refs, **no named regulation** — those are later packs). Owner reviews the spec
   before any test is written. Mirrors F7's distilled `scan-api-spec.md`.
2. **Pack shape:** **control-centric** — each control lists the `finding_type`s
   that `breached_by` it. Reads as a compliance control catalog.
3. **ControlState N/A:** **honest N/A** — `fail` if a mapped finding is present;
   `pass` only if the control's types were actually evaluated by the scan and none
   present; `not_applicable` if none of its types were evaluated (never fake a
   pass for something unchecked). ⇒ the mapping engine needs an injected
   `evaluated_types` set (engine has no taxonomy registry; DI matches the codebase).

**Architecture law (the headline for F8):** detection ≠ mapping. The engine stays
framework-neutral (`finding_type` only); *all* control/regulation naming lives in
`control_plane/packs/*.yaml` as **data, not code**. control_plane may import
`attestable_engine`; engine/cli must never import control_plane.

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (paste proof)
- [x] 3. Minimum code → **GREEN** (2026-07-04)
- [x] 4. Refactor; tests stay green (tuple immutability from review)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Every finding fixed; reviews re-run clean (sec CRITICAL withdrawn; code HIGH fixed; qa PASS)
- [ ] 7. Human read the diff → commit  ← **you are here**

## 1. Architect design (2026-07-04)

### Modules (`packages/control_plane/src/attestable_control_plane/mapping/`)
- `pack.py` — `Control(id, title, breached_by)`, `PackRef(id, version)`,
  `Pack(pack: PackRef, controls: list[Control])` (all frozen), `PackError`, and
  `load_pack(yaml_text) -> Pack` (yaml.safe_load + M1–M4 fail-closed validation).
  Plus `load_baseline() -> Pack` resolving the shipped pack via
  `importlib.resources` (gap #3).
- `evaluate.py` — `ControlState = Literal["pass","fail","not_applicable"]`,
  `ControlResult(id, title, state, breaching_types)` (sorted, empty unless fail),
  `EvaluationResult(pack_ref, results)` (results in pack order), and
  `evaluate_pack(pack, findings, *, evaluated_types: set[str]) -> EvaluationResult`.
- `packs/baseline.yaml` — shipped B0–B5 data (safe YAML).

### Data flow
`load_pack(text)` [M1–M4] → `Pack` → `evaluate_pack(pack, findings, evaluated_types)`:
per control → FAIL if any finding type ∈ breached_by (M7); else PASS if any
breached_by type ∈ evaluated_types (M8); else NOT_APPLICABLE (M9). Collect + sort
breaching types (M10), attach PackRef (M11), results in pack order, byte-identical
on re-eval (M12).

### Ordered TEST LIST (56) — `packages/control_plane/tests/test_mapping.py`
- **A. Pack load + validation (1–18, M1–M4):** valid-minimal; missing pack/controls
  key; not-a-mapping; controls-not-list; empty-controls; missing control
  id/title/breached_by; empty id/title/breached_by; breached_by-not-list;
  duplicate-id; non-string-in-breached_by; unknown top-level/control keys ignored;
  safe_load rejects `!!python/object` → PackError.
- **B. Baseline content (19–34, B0–B5):** loads; id=baseline; version=1; each of
  the 4 controls present with its breached_by types; exactly 4 controls; all six
  finding_types covered; ids vendor-neutral (no regulation names).
- **C. ControlState (35–40, M7–M9):** fail-when-finding; pass-when-evaluated-clean;
  n/a-when-type-unevaluated; never-pass-when-unevaluated; fail-multiple; fail>pass.
- **D. Result record (41–49, M10–M11):** id/title/state fields; breaching types on
  fail / empty on pass / empty on n/a; breaching sorted; pack_ref present; results
  in pack order.
- **E. Integration (50–54, M7–M12):** mixed states; all-pass; all-n/a; many-to-many;
  only-evaluated-types-count.
- **F. Determinism (55–56, M12):** identical twice; output independent of finding
  input order (sorted, no set-iteration/clock/random leak).

### Acceptance criteria
56 red-before-green; 3 artifacts (pack.py, evaluate.py, baseline.yaml); pytest +
ruff + mypy --strict clean; **architecture law** (control→engine ok; engine/cli
never →control; **no regulation named in code — only in the pack YAML**); honest
N/A (never pass an unevaluated control); deterministic; reviewers + qa PASS;
human-approved commit.

### Spec gaps (assumptions, none block the list)
#1 `PackError` = single `Exception` subclass w/ message. #2 OQ-1 `evaluated_types`
injected (no default) — engine taxonomy export deferred to F9. #3 baseline path via
`importlib.resources`. #4 `ControlState` = `Literal`, not Enum (JSON-friendly).
#5 breaching sort = alphabetical asc. #6 `from attestable_engine import Finding`.

## 2. Red proof

56 tests written in `packages/control_plane/tests/test_mapping.py` before any
production code. First run — the `mapping/` modules don't exist, so collection
fails (canonical "no code yet" red):

```
ERROR collecting packages/control_plane/tests/test_mapping.py
  packages/control_plane/tests/test_mapping.py:17: in <module>
      from attestable_control_plane.mapping.evaluate import (
  E   ModuleNotFoundError: No module named 'attestable_control_plane.mapping.evaluate'
!!! Interrupted: 1 error during collection !!!
```

Dep note: `pyyaml` needed for `yaml.safe_load`. Added to control_plane runtime deps.

## 3 + 4. Green & refactor

Implemented the 3 architect artifacts:
- `mapping/pack.py` — `Control`/`PackRef`/`Pack` (frozen), `PackError`,
  `load_pack(yaml_text)` (yaml.**safe_load** + fail-closed M1–M4 validation via
  `_parse_ref`/`_parse_control`; bool excluded from the int version check so
  `version: true` isn't read as 1), and `load_baseline()` via `importlib.resources`.
- `mapping/evaluate.py` — `ControlState` Literal, `ControlResult`,
  `EvaluationResult`, `evaluate_pack(pack, findings, *, evaluated_types)`
  implementing M7 (fail) / M8 (pass, evaluated+clean) / M9 (honest N/A); breaching
  types = sorted intersection of `breached_by` ∩ present (M10); results in pack
  order; `PackRef` attached (M11); pure function, deterministic (M12).
- `packs/baseline.yaml` — B0–B5.

**Structural decision (flag for human read):** the pack YAML lives *inside* the
importable package at `src/attestable_control_plane/packs/baseline.yaml`, not the
sibling `packages/control_plane/packs/` placeholder (which I removed). Reason:
`importlib.resources` + wheel packaging require package data to sit inside the
package; it is still logically "control_plane's packs" per the architecture law.
Dep added: `pyyaml>=6` (control_plane runtime) + `types-PyYAML` (root dev, mypy).

**Final run:** `uv run pytest -q` → **420 passed** (364 at F7 + 56 F8). ruff clean;
`uv run mypy .` --strict clean (44 files). No refactor needed — green code was
already lint/type clean.

## 5 + 6. Review findings

Three reviewers ran on the diff in parallel; findings resolved in one pass, then
security + code reviewers re-verified.

**security-reviewer — 1 CRITICAL (withdrawn, false positive).**
- CRITICAL claimed hatchling wouldn't ship `baseline.yaml` in the wheel (would
  need an explicit `include`). **Verified false by building the wheel**
  (`uv build --wheel packages/control_plane`) and inspecting it —
  `attestable_control_plane/packs/baseline.yaml` is present; hatchling includes
  non-`.py` data files inside the selected package dir by default. Reviewer
  **withdrew** the finding on the evidence. No change made.
- Everything else clean: safe_load-only (no code exec / billion-laughs), fail-closed
  loading, honest N/A never yields a false pass, deterministic output, architecture
  law (engine-only import, vendor-neutral control ids).

**code-reviewer — 1 HIGH (fixed) + 1 LOW (spec-clarified).**
- **HIGH — frozen dataclasses held mutable `list` fields.** `frozen=True` blocks
  field reassignment but not `list.append`, so a caller could mutate a loaded
  `Pack`/result and break M12 determinism. **Fixed:** `Control.breached_by`,
  `Pack.controls`, `ControlResult.breaching_types`, `EvaluationResult.results` are
  now tuples; loader/evaluator build tuples; tests compare tuples.
- LOW — `pack.id` lower-kebab (M13) not validated. Not an M3 fail-closed condition;
  resolved by **clarifying spec M13** (id = any non-empty string; kebab is
  convention). No surprising new validation added.

**qa — PASS.** All rules M1–M14 / B0–B5 covered; red-before-green proven; honest-N/A
(M8 vs M9) and the safe_load M4 test genuinely exercised; no skips. Its two notes
(M13 kebab; `version < 1` untested) addressed: spec M13 clarified + added
`test_load_pack_version_zero_rejected` and `test_load_pack_version_bool_rejected`.

**Final:** `uv run pytest -q` → **422 passed** (58 F8 + F7's 364); ruff + `uv run
mypy .` --strict clean.

## Decisions & open questions

- **Pack location** = `src/attestable_control_plane/packs/baseline.yaml` (inside the
  importable package), not the old sibling `packages/control_plane/packs/`
  placeholder (removed). Required for `importlib.resources` + wheel packaging;
  logically still "control_plane's packs" per the architecture law. Wheel build
  verified to include it.
- **Immutability** = all loaded pack/result containers are tuples, so a scan's
  evidence can't be mutated after the fact (M12). Frozen dataclass alone was
  insufficient (mutable list fields).
- **Honest N/A** = a control is `not_applicable`, never `pass`, when its
  `finding_type`s weren't evaluated — so evidence never overclaims a passed check.
- **OQ-1 (open)** — `evaluated_types` is injected in F8. Production should derive it
  from an engine taxonomy export (the set of `finding_type`s its detectors emit);
  wire when the scan→mapping path is assembled (F9 / hosted). See spec §7.
- **OQ-2/OQ-3 (deferred)** — resource/prompt-entity controls arrive as new pack rows
  (no code change); scalar/weighted control scores are out of scope (categorical
  `ControlState` matches the engine's pass/fail gate). Spec §7.
- **M13 clarified** — `pack.id` is any non-empty string (lower-kebab is convention,
  not enforced) — reconciles §5 wording with the M3 fail-closed list.

## Commit
_Hash + message once the human approves._
