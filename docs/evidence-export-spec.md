# Evidence Export Spec

> Defines the **evidence document** — the pack-driven, deterministic compliance
> record produced from a scan's findings and its control evaluation — and the
> pure `build_evidence(...)` builder. This document is the source of the F9 tests;
> every test cites a rule id here.
>
> **Architecture law (CLAUDE.md / README):** control_plane may import
> `attestable_engine` (Manifest, ScanResult, Finding) and the F8 mapping layer;
> it must never import cli, and it names **no** regulation in code — the pack
> id/version carried into the document is data from the pack.
>
> Status: §1–§7 filled for **F9** (evidence builder). Distilled 2026-07-04 with
> owner sign-off (F9 log §Kickoff); the TDD is external. Signing, zip/multi-file
> bundles, and the scan→map orchestration are **out of scope** (deferred).

Rule prefix: **EV** = evidence document + builder. **OQ** = owner open questions.

## 1. Purpose & scope

The evidence builder is the last step of the compliance layer. It takes the
structured outputs of a completed scan —

- the **Manifest** (F1: `manifest_hash`, `transport`),
- the **ScanResult** (F4: per-severity `summary` + framework-neutral `findings`),
- the **EvaluationResult** (F8: `pack_ref` + per-control `ControlState`s),

plus caller-supplied **provenance** (`generated_at`, `scan_id`) — and emits a
single self-contained, deterministic **evidence document** (JSON) that records
exactly which pack (id + version) judged which controls pass/fail/not-applicable
over which findings. It is a **pure function**: no clock, no RNG, no I/O.

**In scope (F9):** the `Evidence` value + `build_evidence(...)`; the JSON document
format + deterministic serialization; recording the pack ref; faithful (verbatim,
JSON-escaped) finding text.

**Out of scope (deferred):** cryptographic signing (NFR-04); zip/multi-file or
"bundle-of-files" packaging; the connect→scan→detect→score→map orchestration that
feeds this builder; the engine `finding_type` taxonomy export that would source
`evaluated_types` (mapping-pack-spec OQ-1). A human-readable (HTML) evidence
rendering is deferred — F5 already emits an HTML report; F9 is machine evidence.

## 2. Evidence document format (JSON)

- **EV1 — Top-level keys** are exactly:
  `schema_version, generated_at, scan_id, pack, server, summary, controls,
  findings`. No more, no fewer.
- **EV2 — `pack`** = `{"id", "version"}` copied from `EvaluationResult.pack_ref`
  (the required "pack id/version recorded" — backlog).
- **EV3 — `server`** = `{"manifest_hash", "transport"}` from the `Manifest`.
- **EV4 — `summary`** = `{"counts": {"critical","high","medium","low"}, "worst",
  "gate"}` from `ScanResult.score` (`worst` may be `null`).
- **EV5 — `controls`** = a list in `EvaluationResult.results` order; each entry
  `{"id","title","state","breaching_types"}`. `state` ∈
  `{"pass","fail","not_applicable"}`; `breaching_types` is the sorted list carried
  from F8 (empty unless `state == "fail"`).
- **EV6 — `findings`** = a list in `ScanResult.findings` order; each entry
  `{"finding_type","entity_ref","severity","confidence","rationale"}` — the same
  finding shape F5's report emits (consistent wire shape across surfaces).
- **EV7 — `schema_version`** is a string (default `"1.0"`; caller-overridable).

## 3. Builder signature & inputs

- **EV8 — Signature:**
  `build_evidence(manifest, result, evaluation, *, generated_at, scan_id,
  schema_version="1.0") -> Evidence`. Positional inputs are the three structured
  objects; provenance + schema are keyword-only.
- **EV9 — `Evidence`** is a frozen value exposing `.json` — the serialized
  deterministic document string (mirrors F5's `Report.json`). `.json` is the
  artifact a caller persists/signs later.

## 4. Determinism & provenance

- **EV10 — Pure + deterministic.** `build_evidence` calls no clock, no RNG, no
  filesystem. Same `(manifest, result, evaluation, generated_at, scan_id,
  schema_version)` ⇒ **byte-identical** `.json`.
- **EV11 — Provenance is injected, verbatim.** `generated_at` (an ISO-8601 string
  the caller supplies) and `scan_id` are copied into the document unchanged; the
  builder never generates them. This keeps provenance in the record while the
  function stays testable/deterministic (F5 pattern: the clock lives in the
  caller, not the pure core).

## 5. Serialization rules

- **EV12 — Deterministic JSON.** Serialized with sorted object keys and fixed
  separators (compact, no incidental whitespace). List order (controls, findings)
  is preserved from the inputs — only object *keys* are sorted. Re-serializing the
  same inputs is byte-identical (EV10).
- **EV13 — Faithful finding text.** Finding `entity_ref`/`rationale` originate from
  a hostile server and are recorded **verbatim** (JSON-escaped by the encoder),
  **not** stripped of control bytes. Evidence must be a faithful record; the
  terminal/HTML surfaces (CLI, F5 HTML) strip control bytes for *rendering* safety,
  but JSON transport already neutralizes them and stripping would corrupt evidence.

## 6. Test fixtures

- **Full build:** a manifest + scored findings (a mix incl. a `tool.exfiltration`)
  + a baseline `EvaluationResult` ⇒ assert the EV1 key set; `pack` = the pack ref
  (EV2); `server` hash/transport (EV3); `summary` counts/worst/gate (EV4);
  `controls` in order with states + breaching types (EV5); `findings` in order with
  the EV6 fields.
- **Clean scan:** no findings, all types evaluated ⇒ every control `pass`,
  `findings` empty, `summary.gate == "pass"`.
- **Provenance:** the supplied `generated_at`/`scan_id` appear verbatim (EV11).
- **Determinism:** build twice with identical inputs ⇒ identical `.json` (EV10/EV12).
- **Faithful text:** a finding `rationale` containing a control byte survives a
  `json.loads` round-trip unchanged (EV13).
- **schema_version:** default `"1.0"`; an override is echoed (EV7).

## 7. Open questions (owner)

- **OQ-1 — Cross-platform float byte-identity.** `confidence` is serialized via the
  JSON encoder's default float repr (inherited from F5 OQ). Fine for a single host;
  if signed evidence later needs byte-identity across platforms, pin a float format.
- **OQ-2 — Signing / bundle packaging.** NFR-04 signing and any zip/multi-file
  "bundle" wrap the `.json` later; the deterministic `.json` is the signable unit.
- **OQ-3 — `evaluated_types` provenance.** Whether a control was `not_applicable`
  because it was unevaluated is captured only as the resulting `state`; recording
  the evaluated-type set itself in evidence is deferred with the engine taxonomy
  export (mapping-pack-spec OQ-1).
