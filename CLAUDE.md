# Attestable — Agent Constitution

## What this is
MCP security + compliance-evidence platform. Open-core:
- packages/engine, packages/cli  → Apache-2.0 (OPEN)
- packages/control_plane          → proprietary (COMMERCIAL)
Never import control_plane from engine/ or cli/.

## Architecture law: detection ≠ mapping
The engine emits FRAMEWORK-NEUTRAL findings (finding_type only).
It must never name a regulation. Mapping to controls happens
only in control_plane/packs/*.yaml (data, not code). Adding a
domain = a new pack file. If you're tempted to write "if HIPAA"
in the engine, stop — it goes in a pack.

## The law: test-first
No production code without a failing test first.
Detection tests derive from docs/detection-rules-spec.md;
pack tests from docs/mapping-pack-spec.md. If a behaviour
isn't in a spec, stop and ask — do not invent rules.

## Commands
test:  uv run pytest -q
lint:  uv run ruff check . && uv run mypy .
run:   uv run attestable scan <url>

## Definition of done
green tests + code-reviewer pass + security-reviewer pass
+ qa pass + human read the diff. Only then commit.

## Security rules (this is a security product)
- Scanner must block link-local (169.254.0.0/16) & RFC-1918 targets.
- Never commit secrets. Keys live in .env (git-ignored).
- Hosted path scans public servers only; stdio = CLI only.

## Commit format
feat|fix|test|chore(scope): summary
