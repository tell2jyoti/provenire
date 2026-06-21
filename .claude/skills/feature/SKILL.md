---
name: feature
description: Run the full test-first feature loop end to end.
argument-hint: [feature-name]
---
Drive feature "$1" through the loop in docs (Build Blueprint §06):
1. Spawn the architect subagent → design + ordered TEST LIST + acceptance criteria.
2. Write those tests FIRST. Run them. Confirm they FAIL (red). Show me the red.
3. Write the minimum code to pass. Run. Confirm green.
4. Refactor; tests stay green.
5. Spawn code-reviewer, security-reviewer, qa subagents on the diff.
6. Fix every finding; re-run reviews until clean.
7. Stop and ask me to read the diff before committing.
