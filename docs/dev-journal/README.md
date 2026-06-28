# Dev journal — the "don't re-explain" record

This directory is how a future session (or teammate) picks up **exactly** where
the last one stopped, without anyone re-explaining context.

## Files
- **`STATUS.md`** — the live pointer: active feature, current loop step, branch,
  last red/green, open findings, next action, and the F1–F9 backlog. **Read this
  first** on every resume — that's what `/resume` does.
- **`F<n>-<slug>.md`** — one durable log per feature (copy `_TEMPLATE.md`),
  recording the architect's design, the red proof, review findings, and
  decisions. The *why*, not just the *what*.
- **`_TEMPLATE.md`** — the per-feature template.

## Who writes here
The **orchestrator** (the `feature` skill / main agent) writes the journal. The
four review agents (architect, code-reviewer, security-reviewer, qa) stay
**read-only by design** — a reviewer cannot approve or journal its own work; the
orchestrator pastes their findings in. This keeps the review gate honest.

## The loop (blueprint §06) — what gets recorded at each step
1. Architect → design + ordered TEST LIST + acceptance criteria → §1 of the log.
2. Tests written first, run, shown **RED** → paste proof in §2.
3. Minimum code → **GREEN** → §3.
4. Refactor; tests stay green → §3/4.
5. code-reviewer + security-reviewer + qa on the diff → §5.
6. Fix every finding; re-run until clean → §6.
7. Human reads the diff → commit hash → §Commit. Then update `STATUS.md`.

## Resuming
Run `/resume` (or just read `STATUS.md`). It reports the active feature, the loop
step, open findings, and the single next action — then waits for your go-ahead.

## Relation to other records
- `docs/adr/` — Architecture Decision Records: durable *decisions*. The journal
  links to them; it doesn't replace them.
- `docs/references/` — pinned external docs (MCP spec, etc.) the agents read.
- `CLAUDE.md` — the constitution (rules). The journal is *state*, not rules.
