# F<n> — <feature name>

> Copy to `F<n>-<slug>.md` when the feature starts. The orchestrator fills this
> in as the loop progresses; it is the durable record of *why*, not just *what*.
> Reviewers are read-only — their findings are pasted here by the orchestrator.

- **Layer:** engine | cli | control
- **Branch:** `feature/F<n>-<slug>`
- **Spec source:** docs/detection-rules-spec.md §… | docs/mapping-pack-spec.md §…
- **Started:** YYYY-MM-DD · **Done:** —

## Loop progress (blueprint §06)

- [ ] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [ ] 2. Tests written first, run, **shown RED** (paste proof)
- [ ] 3. Minimum code → **GREEN**
- [ ] 4. Refactor; tests stay green
- [ ] 5. code-reviewer + security-reviewer + qa run on the diff
- [ ] 6. Every finding fixed; reviews re-run clean
- [ ] 7. Human read the diff → commit

## 1. Architect design
_Ordered test list (each derived from a spec rule — cite it). Modules/data flow.
Acceptance criteria. Spec gaps flagged + stopped on._

## 2. Red proof
_The failing-test output, before any production code. A back-filled test is a
faked test — the red must be shown._

## 3 + 4. Green & refactor
_What was implemented; final test run; any refactors._

## 5 + 6. Review findings
_code-reviewer / security-reviewer / qa findings by severity, and how each was
cleared. qa PASS/FAIL._

## Decisions & open questions
_Anything non-obvious a future session would otherwise have to re-derive. Link
ADRs (`docs/adr/`) for architectural calls._

## Commit
_Hash + message once the human approves._
