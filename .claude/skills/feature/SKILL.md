---
name: feature
description: Run the full test-first feature loop end to end.
argument-hint: [feature-name]
---
Drive feature "$1" through the loop in docs (Build Blueprint §06).

First, orient: read `docs/dev-journal/STATUS.md`. If "$1" has no log yet, copy
`docs/dev-journal/_TEMPLATE.md` to `docs/dev-journal/F<n>-<slug>.md` and set the
active feature + branch in STATUS.md. **You** (the orchestrator) own the journal;
the review subagents stay read-only.

1. Spawn the architect subagent → design + ordered TEST LIST + acceptance
   criteria. Record them in §1 of the feature log.
2. Write those tests FIRST. Run them. Confirm they FAIL (red). Show me the red,
   and paste the red proof into §2 of the log — a back-filled test is a faked test.
3. Write the minimum code to pass. Run. Confirm green. Note it in §3.
4. Refactor; tests stay green.
5. Spawn code-reviewer, security-reviewer, qa subagents on the diff. Paste their
   findings into §5 of the log.
6. Fix every finding; re-run reviews until clean (§6). qa must PASS.
7. Stop and ask me to read the diff before committing.

After I approve and you commit: write the commit hash into the log, flip the
feature's row in STATUS.md, and update the "Now" + "Next action" block so the
next session can resume from STATUS.md alone.
