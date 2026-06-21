#!/usr/bin/env bash
# block-secrets.sh — deny a git commit whose staged diff contains a secret.
# PreToolUse(Bash) hook: reads the tool call JSON on stdin, blocks with exit 2.
# Defends the classic leaked-key surprise bill.
set -uo pipefail

cmd=$(jq -r '.tool_input.command // empty')
echo "$cmd" | grep -q 'git commit' || exit 0

staged=$(git diff --cached -U0 2>/dev/null || true)

# Key patterns: AWS keys, Neon/Postgres URLs, generic tokens/secrets by name.
patterns=(
  'AKIA[0-9A-Z]{16}'                              # AWS access key id
  'aws_secret_access_key'                         # AWS secret (by name)
  'postgres(ql)?://[^[:space:]]+'                 # Neon / Postgres connection string
  '(secret|token|api[_-]?key|password)[[:space:]]*[:=][[:space:]]*[^[:space:]]'
)

for p in "${patterns[@]}"; do
  if echo "$staged" | grep -Eiq "$p"; then
    echo "block-secrets: staged diff matches /$p/ — commit blocked. Move it to .env (git-ignored)." >&2
    exit 2
  fi
done
exit 0
