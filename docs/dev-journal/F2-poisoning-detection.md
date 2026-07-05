# F2 — Poisoning detection

> The durable record of *why*, not just *what*. Reviewers are read-only — their
> findings are pasted here by the orchestrator.

- **Layer:** engine
- **Branch:** `chore/agent-context-setup` (F2 built here alongside the context setup; not yet on a dedicated `feature/F2` branch)
- **Spec source:** docs/detection-rules-spec.md §2.2 (Finding) + §3.2 (P0–P3)
- **Started:** 2026-06-28 · **Done:** 2026-06-28 (`2abd153`)

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (paste proof)
- [x] 3. Minimum code → **GREEN** (78 → 97 passed)
- [x] 4. Refactor; tests stay green (code already minimal — pure functions, no refactor needed)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Every finding fixed test-first; all three re-reviewed **clean**
      (code no-blocking, security HIGH cleared, qa PASS); spec-scope items → OQs
- [x] 7. Human read the diff → committed (`2abd153`)

## 1. Architect design

Single pure entrypoint: `detect_poisoning(manifest: Manifest) -> list[Finding]`.
No LLM, no I/O — deterministic regex/unicode scan over the normalized manifest's
text fields. Detection stays framework-neutral: emits `finding_type` only, never
a regulation (CLAUDE.md architecture law).

**New model — `Finding` (§2.2):** frozen dataclass, field order is the contract:
`finding_type, entity_ref, severity, confidence, rationale`.

**Scanned surface (§3.2):** per primitive, concatenated human/agent-facing text
— tools & prompts `name`+`description`; resources `name`+`description` (the
`uri` is the `entity_ref`, not scanned). `entity_ref` = `tool:<name>` /
`prompt:<name>` / `resource:<uri>`. All three kinds scanned.

**Determinism:** findings sorted by `(entity_ref, finding_type)`; at most one
finding per `(entity_ref, finding_type)` pair. Since the pair is unique that
2-key sort is a total order, equivalent to the spec's
`(entity_ref, finding_type, first-match offset)`.

Ordered test list (each rule → +/− tests, per §3.2 acceptance):
1. `Finding` field order + frozen (§2.2)
2. entity_ref schemes for tool/resource/prompt; resource name scanned, ref is uri
3. P0 — realistic benign manifest stays silent (no false positives)
4. P1 — invisible/non-printable unicode (zero-width, BOM, bidi, tags, soft-hyphen)
   detected; finding_type constant across entities; ordinary `\t\n\r` not flagged
5. P2 — hidden-directive seed set detected; benign "instructions"/"prompt" not flagged
6. P3 — egress verb + (destination OR sensitive token) detected; verb-only / dest-only / token-only benign
7. dedup (two P2 patterns → one finding); 3 distinct findings same entity; canonical order + determinism; F2 acceptance shape

Acceptance: given a `Manifest`, returns a deterministic canonically-ordered
`list[Finding]` with correct type/ref/severity/confidence + a citing rationale;
benign → `[]`; every rule P1–P3 has positive and negative tests.

Spec gaps flagged: none new. Pre-existing owner OQ (payload size caps) stays
deferred to F7/adapter — irrelevant to pure detection here.

## 2. Red proof

Tests written first, before `finding.py` / `detect/poisoning.py` existed. Run
collected RED on the missing public symbols (not on assertions — the code did
not exist):

```
ImportError while importing test module '.../tests/unit/test_poisoning.py'
E   ImportError: cannot import name 'Finding' from 'provenire_engine'
    (.../src/provenire_engine/__init__.py)
ImportError while importing test module '.../tests/unit/test_finding_model.py'
E   ImportError: cannot import name 'Finding' from 'provenire_engine'
!!!!!!!!!!!!!!!!!!! Interrupted: 2 errors during collection !!!!!!!!!!!!!!!!!!!!
```

## 3 + 4. Green & refactor

Implemented:
- `src/provenire_engine/finding.py` — `Finding` frozen dataclass (§2.2).
- `src/provenire_engine/detect/poisoning.py` — `detect_poisoning` + three pure
  rule checks (`_check_invisible_unicode` / `_check_directive` /
  `_check_exfiltration`) over `_scanned_entities`. P1 uses unicode category
  `Cc`/`Cf` minus `\t\n\r` (covers the spec's explicit zero-width/bidi/tags
  ranges); P2 is an extensible compiled-pattern tuple; P3 = egress verb AND
  (destination OR sensitive token).
- `detect/__init__.py` + package `__init__.py` — export `Finding`, `detect_poisoning`.

Final run: **78 passed** (F1's 41 + 37 new). `ruff check` clean; `mypy --strict`
clean (15 source files). Code is minimal pure functions — no separate refactor pass.

## 5 + 6. Review findings

All three reviewers ran, fixes applied test-first (new red shown for the
must-fix items before the code change), then **all three re-reviewed clean**:
code-reviewer no blocking (nits cleared), security-reviewer HIGH **CLEARED**
(linear timing re-measured), qa **PASS** (dup-name regression test added).
Final suite **97 passed** (was 78), ruff + mypy --strict clean.

### security-reviewer — **HIGH must-fix: quadratic ReDoS** (FIXED)
The P2/P3 regexes backtracked O(n²) on attacker-controlled text with no outer
timeout (R2 only wraps session/enumeration). Measured 4.34s on `"send "+"a"*50000`
before the fix.
- Fix: bounded every `.`-repetition — `disregard .{0,200}?instructions`,
  `<important|system>.{0,4000}?…`, and `_P3_DESTINATION` email local-part/domain
  caps (`{1,64}@{1,255}\.{2,24}`) + `https?|ftp://\S{1,2048}`.
- Red proof: `test_no_catastrophic_backtracking` (3 payloads) asserted detection
  < 1.0s — failed at 4.34s, passes in ms after the fix.
- MEDIUM/LOW (NFKC/homoglyph/non-Cc-Cf evasion, entity_ref output hygiene): the
  reviewer itself scoped these as faithful-to-spec → **deferred as spec OQs**
  (below), not blocking. SSRF / secret-exposure confirmed clean (no I/O here).

### qa — **PASS** (after two rounds)
Coverage gaps, all added test-first:
- P1 bidi isolates U+2066–U+2069 + zero-width U+200C/U+200D + embedding U+202A
  had no witness → added to the parametrize.
- Rationale *content* never asserted (spec mandates it) → P1 now asserts the
  offending `U+XXXX`; added `test_p2_rationale_quotes_matched_phrase` and
  `test_p3_rationale_names_verb_and_target`.
- P3 `exfiltrate` verb + `secret`/`credentials`/`access_token` tokens → witnessed.
- P2 alternation branches `prior`/`above`/`reveal to`/`alerting` → witnessed.
- Round 2: duplicate-named primitives path was untested → added
  `test_duplicate_named_primitives_both_reported_deterministically` pinning
  current behaviour (both reported, deterministic order) + caveated the
  "total order" comment. qa then PASS.

### code-reviewer — no blocking; nits FIXED
- P3 rationale named only the URL *scheme* → destination now captured in full
  (same edit as the ReDoS fix); asserted by the new P3 rationale test.
- "first/strongest" comment → "earliest match by offset" (no strength ranking).
- `Finding.severity` now `Literal["critical","high","medium","low"]` so
  mypy --strict catches a mistyped severity at the call sites.
- Duplicate-named primitives finding → **OQ** (below), resolved deliberately.

## Decisions & open questions

- **P1 via unicode category, not a hardcoded codepoint list.** `Cc`/`Cf` minus
  `\t\n\r` is a superset of the spec's enumerated ranges and won't drift as new
  format chars appear. The enumerated ranges (incl. bidi isolates) are now each
  tested witnesses.
- **2-key sort, not 3-key.** Offset in the spec ordering is a tiebreaker that
  never fires (the `(entity_ref, finding_type)` pair is unique per entity).
- **Severity/confidence are provisional** (§3.2): inputs to F4 scoring, not final.
- **Bounded regex repetitions are a security control, not a style choice** —
  detection has no outer timeout, so an unbounded `.*?` is a scanner-hang/DoS
  vector. New patterns must keep repetitions bounded (regression test guards it).

**OQ — owner decisions (spec follow-ups; not invented here per CLAUDE.md):**
1. **Duplicate-named primitives.** Two tools both named `t` yield two findings
   with identical `(entity_ref, finding_type)`, tensioning the §3.2 "at most one"
   wording. Kept current behaviour (no cross-entity dedup) — deduping would hide
   a second poisoned tool (false negative). Owner to either amend the §3.2
   wording or add entity_ref disambiguation for duplicates.
2. **Unicode-normalization evasion (§3.2 P1/P2 scope).** Homoglyph
   (`ignоre` w/ Cyrillic о) and fullwidth/compatibility forms bypass P2 with no
   finding. Candidate: NFKC-normalize before matching + a confusables follow-up.
3. **Invisible-but-not-Cc/Cf chars (§3.2 P1 scope).** NBSP (U+00A0, Zs),
   BRAILLE BLANK (U+2800), HANGUL/CHOSEONG fillers render blank yet aren't `Cf`.
   Candidate: an explicit "invisible-but-not-Cc/Cf" set in P1.
4. **Payload size cap** (pre-existing, R6/F7): defence-in-depth alongside the
   bounded regexes; still deferred to the adapter/control layer. The regexes are
   now *linear*, but a linear scan of a multi-MB field (security re-review:
   ~1.1 MB of repeated `<important>` tokens ≈ 5.7s) is still slow — a per-field
   size cap is the necessary complementary control for linear-but-large input.

## Commit

`2abd153` — feat(engine): F2 poisoning detection — invisible-unicode /
hidden-directive / exfil. Owner approved the diff; 10 files, 97 tests green.
