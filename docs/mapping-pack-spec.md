# Mapping Pack Spec

> Defines the **pack file format** that maps framework-neutral engine
> `finding_type`s to compliance **controls** (data, not code), and the **mapping
> engine** that applies a pack to a scan's findings to produce per-control
> `ControlState`s. This document is the source of the F8 pack/mapping tests —
> every test cites a rule id here.
>
> **Architecture law (CLAUDE.md / README):** detection ≠ mapping. The engine
> emits `finding_type` only and never names a regulation. All control/regulation
> naming lives here in `control_plane/packs/*.yaml` as **data**. Adding a
> regulated domain = a new pack file, never an engine change. control_plane may
> import `provenire_engine`; engine/cli must never import control_plane.
>
> Status: §1–§6 filled for **F8** (mapping engine + `baseline` pack). Distilled
> 2026-07-04 with owner sign-off (F8 log §Kickoff); the TDD is external. Named-
> regulation packs (HIPAA/SOC2/…) and the evidence bundle are **F9+**, not here.

Rule-id prefixes: **M** = pack format + mapping-engine semantics; **B** =
`baseline` pack content; **OQ** = owner open questions.

## 1. Purpose & scope

The mapping engine is the first step of the compliance layer. It takes:

- a **pack** (loaded from `packs/*.yaml`), and
- a **scan result** — the engine's framework-neutral `Finding`s
  (`ScanResult.findings`) plus the set of `finding_type`s the scan **evaluated**,

and emits one **`ControlState`** per control in the pack: `pass`, `fail`, or
`not_applicable`. It names controls, never regulations-by-inference; it runs no
detection of its own.

**In scope (F8):** the pack YAML format + loader/validation; the control-centric
`finding_type`→control mapping; `ControlState` (pass/fail/not_applicable);
one shipped pack `packs/baseline.yaml`; deterministic, ordered output.

**Out of scope (F9+):** the evidence bundle/export (F9); named-regulation packs;
scalar/weighted control scores; remediation text; persistence.

## 2. Pack file format (YAML)

- **M1 — Top level.** A pack is a YAML mapping with exactly two required keys:
  `pack` (metadata, §5) and `controls` (a non-empty list). Unknown top-level keys
  are ignored (forward-compat); missing/mistyped required keys are a load error.
- **M2 — Control entry.** Each item of `controls` is a mapping with required keys
  `id` (non-empty str, unique within the pack), `title` (non-empty str), and
  `breached_by` (a non-empty list of `finding_type` strings). Unknown control
  keys are ignored.
- **M3 — Loader fails closed.** `load_pack` raises a typed `PackError` (never
  silently drops or partially loads) on: not a mapping; missing `pack`/`controls`;
  `controls` not a list or empty; a control missing a required key; a duplicate
  control `id`; an empty `breached_by`; a non-string in `breached_by`. A security
  product must not run a scan against a malformed policy and report a false pass.
- **M4 — Pure data.** A pack contains no executable content and is loaded with a
  safe YAML loader (`yaml.safe_load`) — never `load`/`unsafe_load`. `finding_type`
  strings in `breached_by` are opaque to the loader (not validated against the
  engine taxonomy at load time — that is the N/A rule's job, §4).

## 3. `finding_type` → control mapping

- **M5 — Control-centric.** The mapping is expressed as `control.breached_by =
  [finding_type, …]`: a control is breached by any of the listed types. The
  relation is many-to-many — a `finding_type` may appear under multiple controls,
  and a control may list multiple types.
- **M6 — Framework-neutral input.** The engine `finding_type`s the baseline maps
  (from `detection-rules-spec` §3.2/§3.3) are exactly:
  `tool.poisoning`, `tool.invisible_unicode`, `tool.exfiltration`,
  `tool.over_privilege`, `tool.missing_schema`, `tool.unbounded_schema`.

### `baseline` pack content (B-rules)

- **B0 — Metadata.** `pack.id = "baseline"`, `pack.version = 1`.
- **B1 — `MCP-INJECTION`** "Tool metadata is free of prompt-injection / hidden
  directives" — `breached_by: [tool.poisoning, tool.invisible_unicode]`.
- **B2 — `MCP-EXFIL`** "Tool metadata exposes no data-exfiltration affordance" —
  `breached_by: [tool.exfiltration]`.
- **B3 — `MCP-LEASTPRIV`** "Tools request least privilege" —
  `breached_by: [tool.over_privilege]`.
- **B4 — `MCP-SCHEMA`** "Tool input schemas are present and bounded" —
  `breached_by: [tool.missing_schema, tool.unbounded_schema]`.
- **B5 — Coverage.** The four baseline controls together cover all six §M6
  `finding_type`s (no engine detection is left unmapped). Control ids are
  vendor-neutral ("MCP-…"), naming **no** regulation.

## 4. `ControlState` (pass / fail / not_applicable)

Evaluation input: the pack, the scan's `Finding`s, and `evaluated_types` — the
set of `finding_type`s the scan actually checked for (injected; see OQ-1).

- **M7 — FAIL.** A control is `fail` iff at least one `Finding` in the scan has a
  `finding_type` ∈ `control.breached_by`.
- **M8 — PASS.** A control is `pass` iff it is not `fail` **and** at least one of
  its `breached_by` types ∈ `evaluated_types` (the scan looked and found nothing).
- **M9 — NOT_APPLICABLE.** A control is `not_applicable` iff none of its
  `breached_by` types ∈ `evaluated_types` — the scan never evaluated any breaching
  condition, so neither pass nor fail can be asserted honestly. A control is never
  `pass` for a check that did not run.
- **M10 — Result record.** Evaluation returns one result per control **in pack
  order**, each carrying: control `id`, `title`, `state`, and (for `fail` only)
  the sorted list of breaching `finding_type`s present — the evidence linkage F9
  will cite. Non-fail results carry an empty breaching list.
- **M11 — Pack ref.** The result set records the `PackRef` (`id`, `version`) of
  the pack it was produced from, so downstream evidence (F9) cites the exact pack.
- **M12 — Determinism.** Same `(pack, findings, evaluated_types)` ⇒ byte-identical
  ordered result. No clock, no randomness, no set-iteration order leaking into
  output (breaching types are sorted).

## 5. Pack metadata (id, version)

- **M13 — `pack.id`** is a non-empty string identifying the pack (`baseline`);
  lower-kebab is the authoring convention but is **not** enforced by the loader
  (not a fail-closed condition — a valid id is any non-empty string).
  **`pack.version`** is an integer ≥ 1 (a boolean is rejected — `version: true`
  must not be read as `1`).
- **M14 — Version policy.** Bump `pack.version` on any change to the set of
  controls or any `breached_by` list (a mapping change downstream evidence must be
  able to distinguish). Title-only wording fixes may bump at author discretion.

## 6. Test fixtures

- **Shipped pack:** `packs/baseline.yaml` (the real B0–B5 pack) — loaded and
  asserted in tests, not a throwaway.
- **Loader fixtures (M3):** malformed packs (missing keys, duplicate id, empty
  `breached_by`, non-list `controls`, non-string type) — each expects `PackError`.
- **State fixtures (M7–M9):** with `evaluated_types` = all six §M6 types:
  a `tool.exfiltration` finding ⇒ `MCP-EXFIL` **fail**, others **pass**; no
  findings ⇒ all four **pass**. With `evaluated_types` omitting a control's types
  ⇒ that control **not_applicable** while a present finding still drives **fail**
  on its own control.
- **Determinism fixture (M12):** evaluate the same inputs twice ⇒ identical
  ordered results.

## 7. Open questions (owner)

- **OQ-1 — `evaluated_types` source.** F8 injects it (unit-testable, DI-consistent).
  In production it should come from the engine advertising its taxonomy (the set of
  `finding_type`s its detectors can emit) rather than a hand-maintained list.
  Deferred: add an engine taxonomy export and wire it when the scan→mapping path is
  assembled (F9 / hosted). Until then callers pass the set explicitly.
- **OQ-2 — Resource/prompt entities.** Today all six types are `tool.*`. When
  `resource.*`/`prompt.*` detections land, the baseline gains controls; the
  control-centric format absorbs this without a code change (new pack rows).
- **OQ-3 — Scalar control scores / weighting.** Out of scope; `ControlState` is
  categorical for F8 (matches the engine gate being pass/fail, not a number).
