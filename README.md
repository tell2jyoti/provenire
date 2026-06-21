# Attestable

MCP security + compliance-evidence platform. Open-core monorepo, built test-first.

| Package | License | What it is |
| --- | --- | --- |
| `packages/engine` | Apache-2.0 (OPEN) | Framework-neutral MCP detection engine |
| `packages/cli` | Apache-2.0 (OPEN) | Command-line wrapper around the engine |
| `packages/control_plane` | Proprietary (COMMERCIAL) | Mapping engine, packs, evidence, API |

**Architecture law:** detection ≠ mapping. The engine emits framework-neutral
findings (`finding_type` only) and never names a regulation; mapping to controls
lives in `packages/control_plane/packs/*.yaml` as data. Adding a regulated domain
is a new pack file, never an engine change.

See `docs/attestable-build-blueprint-v1.html` for the engineering workflow and
`CLAUDE.md` for the agent constitution.

## Develop

```sh
uv sync                       # create the venv and generate uv.lock
uv run pytest -q              # fast unit tests
uv run ruff check . && uv run mypy .
```

Secrets live in `.env` (copy from `.env.example`; git-ignored).
