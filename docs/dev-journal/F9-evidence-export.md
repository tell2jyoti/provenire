# F9 — Evidence export

> Durable record of *why*, not just *what*. Reviewers are read-only — the
> orchestrator pastes their findings here. **Final Phase-1 feature.**

- **Layer:** control (third `control_plane` / COMMERCIAL feature)
- **Branch:** `chore/agent-context-setup` (F1–F8 all landed here)
- **Spec source:** `docs/evidence-export-spec.md` (distilled here — was absent)
- **Started:** 2026-07-04 · **Done:** 2026-07-04 (`0f01be6`)

## Kickoff decisions (owner, 2026-07-04)

Asked before writing the spec (no spec existed; TDD is external). All three chose
the recommended option:

1. **Scope = builder only.** A pure, deterministic `build_evidence(...)` that
   assembles a self-contained evidence document from structured inputs and records
   the pack `PackRef`. **Deferred:** signing (NFR-04), zip/multi-file packaging,
   full connect→scan→map orchestration, and the engine taxonomy export for
   `evaluated_types` (mapping-pack-spec OQ-1). Mirrors F5's pure `build_report`.
2. **Format = new JSON document from structured inputs** (Manifest + ScanResult +
   EvaluationResult). Sections: `schema_version, generated_at, scan_id, pack,
   server, summary, controls, findings`. No re-parsing of F5's `Report.json`.
3. **Provenance = injected params.** `generated_at` + `scan_id` are explicit
   arguments (builder never calls the clock / RNG), so the document carries
   when/which-run provenance yet stays deterministic-given-inputs. Matches F5
   keeping the clock out of the pure core.

**Architecture law:** control_plane imports `provenire_engine` (Manifest,
ScanResult, Finding) + F8 mapping; never cli; **no regulation named in code** —
the pack id/version is data carried through from the pack.

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (paste proof)
- [x] 3. Minimum code → **GREEN** (2026-07-04)
- [x] 4. Refactor; tests stay green (mypy nits only)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Every finding fixed; reviews re-run clean (sec 0; code MEDIUM fixed; qa PASS)
- [x] 7. Human read the diff → commit (`0f01be6`, 2026-07-04)

## 1. Architect design
### Module & data flow (`.../evidence/bundle.py`)
`Evidence` = frozen dataclass with `json: str` (mirrors F5 `Report`). `build_evidence(
manifest, result, evaluation, *, generated_at, scan_id, schema_version="1.0")`:
builds a `_payload` dict with the 8 EV1 keys — `pack` from `evaluation.pack_ref`
(EV2), `server` from the Manifest (EV3), `summary` from `result.score` (EV4),
`controls` from `evaluation.results` in order (EV5), `findings` from
`result.findings` in order (EV6, same finding shape F5 emits) — then
`json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))`
(EV12). Pure: no clock/RNG/IO (EV10); provenance copied verbatim (EV11); finding
text NOT stripped (EV13).

### Ordered TEST LIST (39) — `packages/control_plane/tests/test_evidence.py`
- **A. Builder/Evidence (1–6, EV7/8/9):** Evidence frozen; `.json` is str; returns
  Evidence; positional (manifest/result/evaluation) vs keyword-only
  (generated_at/scan_id/schema_version); schema_version default "1.0".
- **B. Document shape (7–9, EV1/7):** parses as dict; top-level keys = exact 8-set;
  schema_version override respected.
- **C–G. Sections (10–30):** pack id/version from pack_ref (EV2); server
  hash/transport from manifest (EV3); summary counts/worst(null when none)/gate
  (EV4); controls list, in eval order, 4 fields, valid states, breaching empty
  unless fail, sorted (EV5); findings list, in scan order, 5 fields, values match
  (EV6).
- **H. Determinism/provenance (31–33, EV10/11):** identical inputs → identical
  bytes; generated_at + scan_id verbatim.
- **I. Serialization/faithful text (34–36, EV12/13):** keys sorted; compact
  separators; a control byte in `rationale` survives a `json.loads` round-trip.
- **J. Full-build fixtures (37–39):** mixed pass/fail/NA (exfiltration + partial
  evaluated_types); clean scan → all pass, worst null, findings empty; determinism
  byte-identical.

### Acceptance criteria
39 red-before-green; `evidence/bundle.py` implemented; pytest + ruff + mypy --strict
clean; **architecture law** (imports engine + F8 mapping; never cli; no regulation
in code); pure + deterministic (byte-identical); provenance injected verbatim;
finding text faithful (not stripped); reviewers + qa PASS; human-approved commit.

### Spec gaps (none block)
No STOP. OQ-1 float byte-identity (F5-inherited), OQ-2 signing/bundling, OQ-3
evaluated_types-in-evidence — all deferred per spec §7; F9 is the builder only.

## 2. Red proof

39 tests written in `packages/control_plane/tests/test_evidence.py` before any
production code. First run — `evidence/bundle.py` doesn't exist, so collection
fails (canonical "no code yet" red):

```
ERROR collecting packages/control_plane/tests/test_evidence.py
  packages/control_plane/tests/test_evidence.py:22: in <module>
      from provenire_control_plane.evidence.bundle import Evidence, build_evidence
  E   ModuleNotFoundError: No module named 'provenire_control_plane.evidence.bundle'
!!! Interrupted: 1 error during collection !!!
```

## 3 + 4. Green & refactor

Implemented `evidence/bundle.py`: `Evidence` frozen dataclass (`json: str`) +
`build_evidence(manifest, result, evaluation, *, generated_at, scan_id,
schema_version="1.0")`. `_payload` assembles the 8 EV1 keys from the three
structured inputs (`_control_dict`/`_finding_dict` helpers); `json.dumps(...,
sort_keys=True, ensure_ascii=True, separators=(",", ":"))` for the deterministic
artifact (EV12). Pure — no clock/RNG/IO. `_SEVERITIES` typed `tuple[Severity, ...]`
so the `counts` index is mypy-strict clean (F5 pattern).

**Final run:** `uv run pytest -q` → **461 passed** (422 at F8 + 39 F9). ruff clean;
`uv run mypy .` --strict clean (46 files). No refactor beyond two mypy-strict nits
fixed at green (Severity-typed `_SEVERITIES`; removed an unused `type: ignore` in
the test).

## 5 + 6. Review findings

Three reviewers ran on the diff in parallel; the one finding fixed in a single
pass, then re-verified.

**security-reviewer — 0 findings (clean).** Confirmed the load-bearing EV13
decision is safe: recording hostile finding text verbatim is fine because
`json.dumps(ensure_ascii=True)` escapes control bytes to `\uXXXX` and JSON string
boundaries can't be broken — evidence stays faithful *and* inert. Determinism/purity
(no clock/RNG/IO; immutable tuple inputs; sort_keys+compact separators), provenance
injection, no info disclosure beyond intent, and architecture law all verified.

**code-reviewer — 1 MEDIUM (fixed).** The `_evaluation` test helper had a
`type: ignore[assignment]` masking a `frozenset` default vs a `set[str]` hint.
**Fixed** to the `None`-default + conditional pattern (matching `_build`); the
`type: ignore` is gone. No production-code findings — implementation mirrors F5's
builder, boundary respected, no dead code.

**qa — PASS.** All 13 EV rules covered; red-before-green proven; the determinism
(byte-identity), faithful-text (control-byte round-trip), and provenance (distinct
non-default values) tests are genuine, not tautologies; no skips.

**Final:** `uv run pytest -q` → **461 passed** (39 F9 + F8's 422); ruff + `uv run
mypy .` --strict clean.

## Decisions & open questions

- **Faithful vs stripped text (EV13)** — evidence records finding
  `entity_ref`/`rationale` **verbatim** (JSON-escaped), the *opposite* of the API
  response / CLI / HTML surfaces which strip control bytes for rendering safety.
  Rationale: evidence must be a faithful record; JSON transport already neutralizes
  control bytes. Security-reviewer confirmed safe.
- **Injected provenance (EV11)** — `generated_at`/`scan_id` are caller-supplied so
  the builder stays a pure, deterministic function (F5 pattern: clock lives in the
  caller). The `.json` is the byte-identical, signable unit.
- **Builder-only scope** — no signing, no zip/multi-file bundle, no scan→map
  orchestration, no engine taxonomy export. Deferred (spec §7).
- **OQ-1 (open)** — cross-platform float byte-identity for `confidence` (F5-inherited);
  pin a float format if signed evidence later needs cross-host byte-identity.
- **OQ-3 (open)** — recording the `evaluated_types` set in evidence (vs only the
  resulting `not_applicable` state) is deferred with the engine taxonomy export
  (mapping-pack-spec OQ-1).
- **End of Phase 1** — F9 completes the F1–F9 backlog. Next phase: wire the
  end-to-end scan→map→evidence path (+ engine taxonomy export for `evaluated_types`),
  the live MCP transport adapter (F1/F6 C6 stub), persistence/`report_url` (F5/F7),
  and named-regulation packs (HIPAA/SOC2) as new pack files.

## Commit

`0f01be6` — feat(control): F9 evidence export — deterministic pack-driven evidence
document, injected provenance, faithful finding text. Human-approved 2026-07-04.
Suite 461 passed; ruff + mypy --strict clean. **Completes Phase 1 (F1–F9).** STATUS
flip in the follow-up chore.
