# F3 — Over-privilege & schema

> The durable record of *why*, not just *what*. Reviewers are read-only — their
> findings are pasted here by the orchestrator.

- **Layer:** engine
- **Branch:** `chore/agent-context-setup`
- **Spec source:** docs/detection-rules-spec.md §3.3 (O0–O3); derived from TDD §07,
  PRD FR-03, Blueprint §09; finding_type `tool.over_privilege` from TDD §08.
- **Started:** 2026-06-28 · **Done:** —

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (paste proof)
- [x] 3. Minimum code → **GREEN** (123 passed)
- [x] 4. Refactor; tests stay green (pure functions — no refactor needed)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Every finding fixed test-first; all three re-reviewed **clean**
      (code no-blocking, security LOW cleared, qa PASS); spec-scope items → OQs
- [ ] 7. Human read the diff → commit  ← **awaiting owner**

## 1. Architect design

**Spec gate first.** §3.3 was a stub; filled it from the source docs (TDD §07
"over-privileged primitives (shell/file/SQL/egress), missing/unbounded schema",
PRD FR-03 P0, Blueprint §09) — no invented rules. finding_type taxonomy: reused
`tool.over_privilege` (TDD §08); introduced `tool.missing_schema` /
`tool.unbounded_schema` for the two schema conditions → flagged as owner OQ
(docs name no schema finding_type; could be one `tool.weak_schema`).

Single pure entrypoint `detect_over_privilege(manifest) -> list[Finding]`.
**Tools only** (capabilities + `input_schema` are tool concepts; resources/prompts
carry neither). Three independent checks per tool, then sort by
`(entity_ref, finding_type)`.

Ordered test list (each → +/− tests, §3.3 acceptance):
1. O1 capability detected — shell / file-write / raw-sql / egress (parametrized)
2. O1 property-name signal (`sql_query` param ⇒ raw-sql) — schema names are surface
3. O1 multiple capabilities → one finding, rationale lists all
4. O1 benign (send_email / get_cal) not flagged
5. O2 empty `{}` schema flagged; no-arg `{"type":"object","properties":{}}` NOT
   flagged; real schema not flagged
6. O3 unbounded string / unbounded array / open additionalProperties flagged;
   bounded string (maxLength/enum/pattern/format) not flagged
7. O2/O3 mutually exclusive
8. tools-only scope (hazard text in resource/prompt → nothing)
9. two findings same tool; canonical order + determinism; O0 benign manifest
   silent; F3 acceptance shape

Acceptance: deterministic canonically-ordered `list[Finding]`, correct
type/ref/severity/confidence + citing rationale; benign → `[]`; every rule O1–O3
has positive and negative tests.

## 2. Red proof

Tests written before `detect/over_privilege.py` existed; collected RED on the
missing public symbol:

```
ImportError while importing test module '.../tests/unit/test_over_privilege.py'
E   ImportError: cannot import name 'detect_over_privilege' from 'attestable_engine'
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
```

## 3 + 4. Green & refactor

Implemented `src/attestable_engine/detect/over_privilege.py`:
- O1 `_check_over_privilege` — capability seed sets (shell/file-write/raw-sql/
  egress) over `name` + `description` + schema property names (underscores→spaces
  so phrase seeds match identifiers); one `tool.over_privilege` finding listing
  all capabilities (high / 0.6).
- O2 `_check_missing_schema` — empty/absent schema → `tool.missing_schema`
  (medium / 0.7); no-arg `{"type":"object","properties":{}}` excluded.
- O3 `_check_unbounded_schema` — string w/o maxLength|enum|pattern|format, array
  w/o maxItems, or `additionalProperties != false` → `tool.unbounded_schema`
  (low / 0.5). Guarded so it never co-fires with O2.
- Wired exports through `detect/__init__.py` + package `__init__.py`.

Final run: **123 passed** (F1 41 + F2 56 + F3 26). ruff + mypy --strict clean (16 files).

## 5 + 6. Review findings

All three reviewers ran, fixes applied test-first, then **all three re-reviewed
clean**: code-reviewer no blocking, security-reviewer LOW **cleared** (ReDoS was
already clean), qa **PASS**. Final suite **161 passed** (was 123), ruff + mypy
--strict clean. (qa's spec-text ratification — O1 case-sensitivity wording — and
security's lowercase-literal-SQL note both folded into §3.3 / the OQs.)

### security-reviewer — ReDoS **clean**; one LOW must-fix (FIXED)
- Verified the capability regexes are **linear** (no nested/overlapping
  quantifiers) — the F2 ReDoS class is absent. Schema walk is top-level only (no
  recursion) → no blow-up on nested/huge hostile schemas.
- **LOW (fixed):** non-string property keys crashed `_capability_text`
  (`k.replace`) and `_check_unbounded_schema` (`", ".join`) — violates R6 no-crash.
  Coerced with `str(k)` / `str(name)`; regression test
  `test_non_string_property_keys_do_not_crash`. (Practical reachability is low —
  JSON-RPC keys are strings — but the normalize guard's "rejects non-string keys"
  claim is actually false; noted for the F1 layer.)
- MEDIUM evasion gaps (top-level non-object schema, JSON-Schema type-arrays,
  nested/top-level-only scan) → spec-scope **OQs** (below), not blocking.

### code-reviewer — no blocking; nits FIXED
- **raw-sql false positives** (also caught by qa): `\bSELECT \b`/`\bDROP \b`
  under IGNORECASE matched prose ("Select a row…"). Fixed: the literal-SQL
  keywords are now **case-sensitive** (spec §3.3 updated); negative test
  `test_o1_sql_keywords_are_case_sensitive` pins it.
- Nit: redundant `schema == {}` clause in O2 → removed. `/bin/s?h` → `/bin/sh`.
  Added the duplicate-name determinism comment to match `poisoning.py`.
- Open property-less object (#2) and untyped/union-typed properties (#3) → OQs.

### qa — verdict **FAIL → re-audit** (gaps closed)
- **FAIL-1:** O2 rationale only asserted truthy → now asserts content
  (`"validation" in rationale`).
- **FAIL-2:** most O1 seed members unwitnessed → `test_o1_capability_detected`
  parametrize extended to one witness per seed alternative (shell/file-write/
  raw-sql/egress).
- Added O2 "lacks type & properties" branch + `{"type":"object"}` boundary pin;
  O3 bounded-array negative; O1 property-name signal for a second class.

## Decisions & open questions

- **Tools-only surface.** Capabilities and `input_schema` are tool concepts; the
  normalized model gives resources/prompts neither, so F3 scans only tools.
- **One `tool.over_privilege` per tool** (not per capability) — matches the TDD
  §08 mapping (finding_type → control); rationale enumerates the capabilities.
- **No-arg vs missing schema.** A real no-arg tool declares
  `{"type":"object","properties":{}}`; only a truly empty/absent `{}` is O2. This
  is how the benign case stays silent without a special-case.
- **Provisional scoring.** Capability detection is heuristic (legitimate use is
  possible) → confidence 0.6, not F2's 0.95; F4/F8 escalate by context (PRD §08:
  raw DB query over a sensitive source → critical).

**OQ — owner decisions (spec follow-ups; not invented here per CLAUDE.md):**
1. **Schema finding_type taxonomy.** Introduced `tool.missing_schema` /
   `tool.unbounded_schema`; docs name neither. Owner: keep two, or merge into one
   `tool.weak_schema`? Affects F8 pack entries.
2. **Capability seed-set breadth** (false-positive/negative tuning) — heuristic
   keyword detection; expected to grow with real-manifest data.
3. **Schema-weakness evasion gaps** (security MEDIUM + code #2/#3) — all
   spec-conformant today, all real false-negatives a hostile server could use:
   - top-level **non-object** schema (`{"type":"string"}`) — whole input is an
     unbounded primitive — escapes O2 (has `type`) and O3 (no `properties`);
   - **open property-less** object (`{"type":"object"}` or empty `properties`
     without `additionalProperties:false`) accepts arbitrary keys, unflagged;
   - JSON-Schema **type-arrays** (`{"type":["string"]}`) dodge O3's `== "string"`;
   - **untyped** property (`{"a":{}}`) accepts any value, unflagged;
   - O1/O3 scan **top-level only** — a nested `sql_query`/unbounded field is
     invisible.
   - the case-sensitive SQL-keyword fix means **lowercase literal SQL**
     (`select * from users`) is no longer caught by the keyword patterns (only by
     the prose seeds) — accepted tradeoff to kill the English-word FP.
   Each needs a deliberate §3.3 expansion (and matching tests), not a silent code
   change.
4. **Duplicate-named tools** — same disposition as F2: both findings kept
   (dropping one hides a finding); §3.3 "≤1 per (entity_ref, finding_type)"
   wording to reconcile.
5. **`normalize._schema` (F1 layer)** docstring claims it "reject[s] non-string
   keys" but `json.dumps` only coerces them in output — the claim is false.
   Tighten the guard or the comment (out of F3 scope; detector now defends itself).

## Commit

_Pending owner review of the diff (loop step 7)._
