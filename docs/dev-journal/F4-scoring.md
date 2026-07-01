# F4 — Scoring

> The durable record of *why*, not just *what*. Reviewers are read-only — their
> findings are pasted here by the orchestrator.

- **Layer:** engine
- **Branch:** `chore/agent-context-setup`
- **Spec source:** docs/detection-rules-spec.md §4 (S0–S5); derived from Blueprint
  §09 (F4 row), TDD §07 (pipeline), PRD (severity/confidence). Consumed by F5
  (report) + F6 (CLI `--fail-on`).
- **Started:** 2026-07-01 · **Done:** —

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (ImportError at collection)
- [x] 3. Minimum code → **GREEN** (204 passed)
- [x] 4. Refactor; tests stay green (pure functions — none needed)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Fixes applied test-first; code + security **re-reviewed clean**, qa **PASS**
      (207 passed, ruff + mypy --strict clean)
- [ ] 7. Human read the diff → commit  ← **awaiting owner**

## 1. Architect design
_Ordered test list (each derived from a spec rule — cite it). Modules/data flow.
Acceptance criteria. Spec gaps flagged + stopped on._

**Spec gate cleared first.** §4 was a stub; filled it from the Blueprint §09 F4
row + owner decisions (this session): output = `ScanResult` (normalized/ranked
`findings` + `ScanScore` aggregate); suppression = confidence floor that **drops**
findings (default `0.5`, inert today). Severity escalation stays in F8 (§3.3
note) — F4 normalizes provisional scores, it does not re-classify.

**Module/data flow (architect).** New `score/scoring.py` with public
`score_findings(findings, *, confidence_floor=0.5, gate_threshold="high")
-> ScanResult`, re-exported via `score/__init__.py` and package `__init__.py`
(mirrors `detect/`). Frozen types `ScanScore` (counts all-four-keys / worst /
gate) + `ScanResult` (findings tuple + score). Pipeline per §4:
S2 clamp→new frozen Finding · S3 floor-suppress (strictly-below dropped) ·
S1 internal rank {crit4 high3 med2 low1}, severity never rewritten · S4 sort
`(rank desc, confidence desc, entity_ref asc, finding_type asc)` · S5 aggregate
over survivors · S0 empty→empty. Pure/deterministic/idempotent.

**Ordered test list (42; each cites S0–S5; +/- per rule).** `tests/unit/test_score.py`:
- S0 (1–2): empty in → empty result; all-suppressed → same shape.
- S1 (3–6): each of crit/high/med/low preserved. _No natural negative — proven by positives._
- S2 (7–12): −0.5→0.0, 1.5→1.0 (pos); 0.75/0.0/1.0 unchanged (neg boundaries);
  clamp yields a **new** Finding, input untouched.
- S3 (13–20): below-floor dropped, `==floor` kept (strictly-below), above kept;
  custom floor below/at; suppressed absent from counts/worst/gate.
- S4 (21–29): rank order crit>high>med>low; tie→confidence desc; tie→entity_ref
  asc; tie→finding_type asc; input-order-independence; determinism; idempotence.
- S5 (30–41): counts all-four-keys incl. zeros + correct totals; worst=highest /
  None; gate fail at/above threshold, pass below, pass when empty; custom
  thresholds crit/med/low.
- Integration (42): comprehensive mixed-severity/confidence/suppression acceptance.

**Acceptance:** all 42 green; signature per §4; frozen types; pure/deterministic/
idempotent; no regulation naming; exports wired; ruff + mypy --strict clean.
**Spec gaps:** none blocking — the four §4 owner-OQs are decisions, not gaps.

## 2. Red proof

42 tests written before `score/scoring.py` existed; collected RED on the missing
public symbols (`score/__init__.py` was empty):

```
ImportError while importing test module '.../tests/unit/test_score.py'.
E   ImportError: cannot import name 'ScanResult' from 'attestable_engine.score'
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
```

## 3 + 4. Green & refactor

Implemented `src/attestable_engine/score/scoring.py`:
- Frozen `ScanScore` (counts / worst / gate) + `ScanResult` (findings tuple + score).
- `_RANK` internal severity→int map (crit4 high3 med2 low1) — NOT on `Finding`.
- `_clamp_confidence` (S2) returns a `dataclasses.replace` copy only when out of
  range; input never mutated.
- `score_findings` (S0–S5): map-clamp → floor filter → two stable sorts
  ((entity_ref, finding_type) asc, then (rank, confidence) reverse) giving the
  S4 total order → aggregate counts/worst/gate over survivors.
- Wired exports via `score/__init__.py` + package `__init__.py`.

Final run: **204 passed** (F1–F3 161 + F4 43). ruff + mypy --strict clean (30 files).
Refactor: none needed — pure functions, no duplication.

## 5 + 6. Review findings

Round 1 — all three ran on the green diff (207 → was 204). **qa PASS** first pass;
code + security each raised the same NaN edge; fixes applied test-first, re-review clean.

### security-reviewer — one "CRITICAL" (NaN) → **false alarm, hardened anyway**
- Claimed `_clamp_confidence` passes NaN through (`max(nan,0.0)=nan`), so a NaN
  finding silently vanishes at S3 (`NaN >= floor` is False). **Investigated: the
  code is `max(0.0, confidence)` — 0.0 is the *first* arg, so `max(0.0, nan)=0.0`;
  NaN already clamps to 0.0.** The exploit assumed the wrong argument order.
  Still: correctness rested on a subtle CPython arg-order detail. **Hardened** with
  an explicit `math.isnan(c) -> 0.0` guard (refactor-safe, self-documenting) and
  **pinned** it with `test_s2_nan_confidence_clamped_to_zero` (+ `+inf→1.0`,
  `-inf→0.0`). These 3 tests were **green on arrival** (behavior already correct)
  — recorded honestly, not a faked red.
- SSRF / secrets / crash-safety: **clean** (pure stage, no I/O; severity KeyError
  on out-of-enum is intentional early-fail per S1, mypy-guarded).

### code-reviewer — no blocking; 2 items **FIXED**
- **Non-blocking:** `ScanScore.gate: str` → `Literal["pass","fail"]` (matches
  `Severity`'s pattern; local annotated so mypy --strict keeps the narrow type).
- **Nit:** `_clamp_confidence` comment misdescribed when `dataclasses.replace`
  fires (only out-of-range) → rewritten. No open-core leaks, no dead code; S0–S5
  independently verified correct.

### qa — verdict **PASS**
- Every rule S0–S5 covered +/− where applicable; S1 positive-only justified
  (out-of-enum is a programming error, mypy Literal). Assertions are strong (exact
  counts dict / ordering / clamped value). Boundary pins present (`==floor` kept,
  0.0/1.0, gate-at-threshold, all-four-count-keys). Determinism/idempotence/
  input-order-independence exercised. Red-before-green genuine (collection red).
- Post-fix delta: +3 NaN/inf tests strengthen S2 coverage; no new gaps.

**Round 2 — re-review clean.** code-reviewer + security-reviewer both re-ran on
the updated diff: **no findings**. Security confirmed NaN cannot vanish (explicit
guard), gate typing tight, determinism/idempotence/crash-safety hold, no new
surface. Code confirmed both round-1 items resolved, no regression/dead code.
Definition of done met (green + 3 reviewers clean); awaiting human diff read.

## Decisions & open questions

**OQ — owner decisions carried from §4 (spec follow-ups; not invented here):**
1. `confidence_floor` default `0.5` is deliberately inert (nothing drops yet) —
   owner sets the real production floor.
2. `gate_threshold` default `"high"` is F4's guess at the CI-fail line; F6 owns
   the final CLI default (`--fail-on`).
3. severity×confidence kept as two ordered sort keys (S4), **not** a single scalar
   risk score — introduce a scalar only if F5/F8 need one.
4. Suppressed findings dropped **silently** (not annotated) — revisit if audit
   needs a "what was suppressed" trail.

## Commit
_Hash + message once the human approves._
