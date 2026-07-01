# F5 — Report

> The durable record of *why*, not just *what*. Reviewers are read-only — their
> findings are pasted here by the orchestrator.

- **Layer:** engine
- **Branch:** `chore/agent-context-setup`
- **Spec source:** docs/detection-rules-spec.md §5 (RP0–RP4); derived from TDD §09
  (Emit JSON+HTML) / §10 (S3 `reports/{scan_id}.{json,html}`, API envelope),
  PRD FR-04 + NFR-04/07, Blueprint §09 F5. Consumes F4 `ScanResult`/`ScanScore`.
- **Started:** 2026-07-01 · **Done:** 2026-07-01 (`f855cde`)

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (ImportError at collection)
- [x] 3. Minimum code → **GREEN** (246 passed)
- [x] 4. Refactor; tests stay green (pure functions — none needed)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. qa FAIL-1 fixed test-first; qa **re-audit PASS**; code + security **clean**
      first pass (248 passed, ruff + mypy --strict clean)
- [x] 7. Human read the diff → committed (`f855cde`)

## 1. Architect design
_Ordered test list (each derived from a spec rule — cite it). Modules/data flow.
Acceptance criteria. Spec gaps flagged + stopped on._

**Spec gate cleared first.** §5 was absent (only a "Test fixtures" section, now
§6); authored §5 from the source docs (TDD §09/§10, PRD FR-04 + NFR-04/07,
Blueprint §09) — no invented rules. Key calls: engine artifact is a **pure,
metadata-free** function of `(manifest, result)` for determinism (RP2); HTML
**escapes** hostile finding text (RP3, XSS); run metadata (scan_id/timestamp)
injected by F6/F7, not the engine.

**Module/data flow (architect).** New `report/builder.py` with public
`build_report(manifest, result, *, schema_version="1.0") -> Report`, re-exported
via `report/__init__.py` + package `__init__.py` (mirrors `score/`). Frozen
`Report(json: str, html: str)`. Internal `_serialize_json` (canonical
`json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",",":"))`,
matching manifest `_canon`) + `_render_html` (`html.escape(str(x), quote=True)`
on every interpolated value; inlined CSS; `<table>` of findings in F4 order).

**Ordered test list (~54; each cites RP0–RP4; +/adversarial).**
`tests/unit/test_report.py`:
- RP0 (empty): JSON `findings:[]`; HTML valid doc with "no findings".
- RP1 (JSON shape): parses; top-level keys exactly {schema_version, manifest_hash,
  transport, summary, findings}; each field maps (hash, transport, summary from
  ScanScore, all-four count keys, worst incl. null, gate); findings order == F4;
  finding keys exact; confidence is a JSON **number**.
- RP2 (determinism): build twice → byte-identical json AND html; different
  result/manifest → different json; **structural absence** of `scan_id`/
  `timestamp`/`duration`/`created_at` keys (not substring bans).
- RP3 (HTML safety): `<!doctype`; complete doc; **own chrome has no
  `<script>`/`<link>`/`src=`/`href=`/`url(`**; summary + findings table present;
  **XSS adversarial** — `<script>`, `"`, `'`, `&`, `<`, `>` in rationale/
  entity_ref rendered as escaped entities; an attacker `https://…`/`<script>` in
  a rationale appears **escaped inside a cell**, never live markup.
- RP4 (completeness): every finding once in both artifacts, in F4 order; no
  phantom/dup; summary counts/worst/gate in both == `result.score`.

**Refinements over architect list (my calls, logged):** the "no external URL"
checks target the report's **own markup** (not a global `https://` ban — a P3
rationale legitimately contains a URL that we render as escaped text); the
"no volatile" checks assert **absent structural keys** (a rationale like `id_rsa`
contains the substring "id"). Byte-identical build is the real determinism proof.

**Acceptance:** all green; signature per §5; frozen `Report`; deterministic
byte-identical; escaped + self-contained HTML; complete/consistent with result;
empty scan valid; exports wired; ruff + mypy --strict clean.
**Spec gaps:** JSON float repr for `confidence` left to `json.dumps` default
(deterministic shortest round-trip repr per platform) — OQ if cross-platform
byte-identity is later required for signed packs.

## 2. Red proof

~38 tests written before `report/builder.py` existed; collected RED on the
missing public symbol (`report/__init__.py` was empty):

```
ImportError while importing test module '.../tests/unit/test_report.py'.
E   ImportError: cannot import name 'build_report' from 'attestable_engine'
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
```

## 3 + 4. Green & refactor

Implemented `src/attestable_engine/report/builder.py`:
- Frozen `Report(json: str, html: str)` + public `build_report(manifest, result,
  *, schema_version="1.0")`.
- `_payload` builds the RP1 dict (schema_version, manifest_hash, transport,
  summary from `ScanScore`, findings in F4 order); serialized canonically via
  `json.dumps(sort_keys=True, ensure_ascii=True, separators=(",",":"))` (RP2).
- `_render_html` builds a standalone `<!doctype html>` doc — inlined `_CSS`, no
  external refs; `_e = html.escape(str(x), quote=True)` on **every** interpolated
  value (RP3); summary + findings `<table>` (or "No findings." when empty, RP0).
- `_SEVERITIES: tuple[Severity, ...]` so counts indexing stays Literal-typed.
- Wired exports via `report/__init__.py` + package `__init__.py`.

Eyeballed a hostile render: entity_ref `tool:"><script>…` → inert
`tool:&quot;&gt;&lt;script&gt;…`; `&` → `&amp;`; attacker URL sits as plain
`<td>` text (no href/src, browsers don't fetch text URLs).

Final run: **246 passed** (F1–F4 207 + F5 39). ruff + mypy --strict clean (32 files).
Refactor: none needed. (Test-helper annotations + `Severity`-typed `_SEVERITIES`
added to satisfy mypy --strict.)

## 5 + 6. Review findings

Round 1 — all three ran on the green diff (246). code + security **clean** (no
findings); qa **FAIL-1** (one HTML-summary coverage gap), fixed test-first.

### security-reviewer — **clean, no findings** (CRITICAL/HIGH/MEDIUM/LOW all none)
- Hammered the XSS surface: every interpolated value goes through
  `_e()=html.escape(str(x),quote=True)`; the only attribute interpolation
  (`class="gate-{gate}"`) is a system Literal, and even a hypothetical quote would
  stay inside the quoted attribute. Attacker URLs / `javascript:`/`data:` render as
  **escaped text**, never linkified (no `href`/`src`). CSS is a static constant.
- Determinism: JSON `sort_keys`+fixed separators; HTML deterministic concatenation
  in F4 order; no clock/uuid/env. JSON built via `json.dumps` (no manual concat) →
  no JSON injection. No crash on hostile input (`str()` first). No secret leakage.

### code-reviewer — **no findings** (nothing blocking, no nits)
- RP1 shape exact; RP2 byte-stable (mirrors manifest `_canon`); RP4 findings keep
  ScanResult order (no re-sort), summary derives from `result.score`; RP0 empty
  path correct. No boundary leaks, no dead code; docstrings cite §5, comments say
  *why*. Matches `score/scoring.py` + `manifest.py` house style.

### qa — verdict **FAIL-1 → fixed → (re-audit pending)**
- **FAIL-1 (RP4):** HTML tests asserted structure ("gate" present, `<table>`), but
  no test proved the HTML **summary values** equal `result.score` (a counts-swap
  mutation would pass). **Fixed test-first:** added
  `test_rp4_html_summary_renders_result_score_values` (gate-fail/worst=critical/
  exact counts) + `test_rp4_html_summary_empty_renders_pass_and_none`. Both green
  (248 passed). These pin already-correct rendering (green on arrival) — recorded
  honestly, not a faked red.
- Everything else PASS: red-before-green genuine; XSS/determinism adversarial tests
  strong; refinement calls (own-markup URL checks, absent-structural-key volatile
  checks) sound.

**Round 2 — qa re-audit PASS.** Confirmed FAIL-1 closed: the HTML summary is now
content-verified against `result.score` (gate/worst/all-four counts) with
exact-value assertions; a counts-swap mutation would fail. No remaining RP0–RP4
gaps. Definition of done met (248 green + code clean + security clean + qa PASS);
awaiting human diff read.

## Decisions & open questions

**OQ — owner decisions carried from §5 (spec follow-ups; not invented here):**
1. Engine artifact deliberately **metadata-free** (no scan_id/timestamp/duration)
   for determinism; F6/F7 wrap it with the run envelope (TDD §10).
2. `schema_version` starts `"1.0"`; bump policy is an owner call.
3. HTML intentionally minimal (summary + findings table); remediation guidance
   (FR-04) + signed artifacts (NFR-04) are later increments.
4. Report carries findings + `manifest_hash` provenance, not full manifest
   primitives (those live in `manifests/{hash}/{ts}.json`) — revisit if F7 needs.

## Commit

`f855cde` — feat(engine): F5 report — deterministic JSON + escaped self-contained
HTML artifact. Owner approved the diff; 7 files, 248 tests green.
