---
name: resume
description: Pick up exactly where the last session stopped — no re-explaining.
---
Re-orient from the durable record; do not ask me to re-explain context.

1. Read `docs/dev-journal/STATUS.md`.
2. If a feature is active, read its log `docs/dev-journal/F<n>-*.md`.
3. Skim `git log --oneline -5` and `git status` to confirm the journal matches
   the working tree (flag any drift).

Then report, concisely:
- **Active feature** and which **loop step** (1–7) we're on.
- **Last red / last green**, and any **open review findings** still to fix.
- The single **next action**.

Stop there and wait for my go-ahead. Don't start writing code or spawning agents
until I confirm — use `/feature <id>` to drive the loop.
