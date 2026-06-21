#!/usr/bin/env bash
# pre-commit-tests.sh — deny a commit if the fast tests fail.
# PreToolUse(Bash) hook: reads the tool call JSON on stdin, blocks with exit 2.
set -uo pipefail

cmd=$(jq -r '.tool_input.command // empty')

if echo "$cmd" | grep -q 'git commit'; then
  uv run pytest -q -m "not slow"
  rc=$?
  # pytest exit codes: 0 = passed, 5 = no tests collected (nothing to fail).
  # Anything else means tests are red — block the commit.
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 5 ]; then
    echo "tests red — commit blocked" >&2
    exit 2
  fi
fi
exit 0
