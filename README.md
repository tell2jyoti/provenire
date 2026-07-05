# Provenire

**MCP security scanning + compliance-evidence generation.** Point it at a
[Model Context Protocol](https://modelcontextprotocol.io) server and it connects,
enumerates the server's tools/resources/prompts, detects security weaknesses in
that surface, scores them, maps the findings to compliance controls, and emits a
deterministic evidence record.

Open-core monorepo, built strictly test-first.

> **Status:** Phase 1 complete (F1–F9) — 461 tests green, `ruff` + `mypy --strict`
> clean. The live MCP transport adapter is the next integration slice; today the
> engine runs against an injected `Session` (in-memory fakes in tests).
> See [`docs/dev-journal/STATUS.md`](docs/dev-journal/STATUS.md).

---

## Why

MCP lets an AI agent call external tools. A malicious or careless MCP server can
smuggle prompt-injection directives inside tool descriptions, over-request
privilege (shell/file/SQL access), expose data-exfiltration affordances, or ship
unbounded input schemas. Provenire audits that attack surface **and** turns the
result into the evidence an auditor asks for — without the detection engine ever
knowing which regulation you care about.

---

## Architecture law: detection ≠ mapping

This is the single most important rule in the codebase.

- The **engine** emits **framework-neutral** findings — a `finding_type` and
  nothing more. It **never names a regulation.**
- **Mapping** framework-neutral findings to named controls happens **only** in
  `packages/control_plane/packs/*.yaml` — as **data, not code**.
- Adding a regulated domain (HIPAA, SOC 2, …) is a **new pack file**, never an
  engine change. If you're tempted to write `if HIPAA` in the engine, stop — it
  goes in a pack.

```
                    ┌──────────────────────────────────────────────┐
                    │  Open core  ·  Apache-2.0  ·  packages/engine │
                    │                                              │
   MCP server ─────▶│  connect ─▶ enumerate ─▶ detect ─▶ score ─▶ report
   (stdio /         │  (F1)       (F1)         (F2,F3)   (F4)     (F5)
    streamable_http)│                                              │
                    └───────────────────────┬──────────────────────┘
                                             │  framework-neutral
                                             │  findings (finding_type only)
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  Control plane  ·  Proprietary               │
                    │  packages/control_plane                      │
                    │                                              │
                    │  map (F8) ──▶ evidence (F9)                  │
                    │  packs/*.yaml    deterministic JSON record   │
                    │  (data, not code)                            │
                    └──────────────────────────────────────────────┘

   packages/cli (F6) wraps the open-core pipeline for stdio / private servers.
   control_plane/api (F7) exposes POST /scan for public servers, behind an SSRF guard.
```

**Import boundary (enforced by convention + review):** `engine/` and `cli/`
must **never** import `control_plane/`.

---

## Packages

| Package | License | What it is |
| --- | --- | --- |
| [`packages/engine`](packages/engine) | **Apache-2.0** (open) | Framework-neutral MCP detection engine: connect → enumerate → detect → score → report |
| [`packages/cli`](packages/cli) | **Apache-2.0** (open) | `provenire scan <target>` — the sanctioned path for stdio / private servers; scans locally, transmits nothing |
| [`packages/control_plane`](packages/control_plane) | **Proprietary** (commercial) | Mapping engine, YAML control packs, evidence export, and the scan API (with SSRF guard) |

`packages/engine` + `packages/cli` are the free, open-source scanner. The control
plane is where framework-neutral findings become named-control evidence.

---

## What it detects

The engine emits six framework-neutral `finding_type`s:

| `finding_type` | Meaning |
| --- | --- |
| `tool.poisoning` | Hidden directives / prompt-injection in tool metadata |
| `tool.invisible_unicode` | Invisible / non-printing Unicode used to conceal content |
| `tool.exfiltration` | Tool metadata exposes a data-exfiltration affordance |
| `tool.over_privilege` | Tool requests more privilege than it needs (shell/file/SQL) |
| `tool.missing_schema` | Tool input has no schema |
| `tool.unbounded_schema` | Tool input schema is present but unbounded |

The baseline pack ([`packs/baseline.yaml`](packages/control_plane/src/provenire_control_plane/packs/baseline.yaml))
maps those into four **vendor-neutral** controls — `MCP-INJECTION`, `MCP-EXFIL`,
`MCP-LEASTPRIV`, `MCP-SCHEMA`. Named-regulation packs are added as separate data
files, never as engine code.

---

## Quickstart

Requires Python ≥ 3.11 and [`uv`](https://docs.astral.sh/uv/).

```sh
uv sync                                # create the venv, resolve the workspace
uv run pytest -q                       # 461 tests
uv run ruff check . && uv run mypy .   # lint + strict type-check
```

That runs the full suite green and type-checks clean — the fastest way to see
what the engine actually does is to read the tests it derives from.

### Scanning a server

> **Integration boundary — read this first.** The detection pipeline
> (connect → enumerate → detect → score → report → map → evidence) is fully
> implemented and unit-tested behind an injectable `connect` factory. The one
> piece not yet wired is the **live MCP transport adapter**, so `scan` against a
> real server today exits `3` (unreachable). Wiring stdio + `streamable_http` is
> the next integration slice ([STATUS.md](docs/dev-journal/STATUS.md)). The CLI
> surface below is the contract that adapter will plug into.

```sh
uv run provenire scan <target> [--fail-on {critical|high|medium|low}] \
                                [--transport {stdio|streamable_http}] \
                                [--timeout SECONDS] [--json] [--output DIR]
```

- **`--fail-on`** sets the CI gate threshold (default `high`): the process exits
  `1` if a finding at or above that severity survives.
- **`--output DIR`** also writes `report.json` + `report.html`.
- **`--json`** emits the machine-readable report to stdout.

**Exit codes** (the CI contract): `0` pass · `1` gate breach · `2` usage error ·
`3` target unreachable · `4` other scan/output failure. A crash is never
conflated with a gate breach.

---

## Security posture

This is a security product, and the scanner itself is a request-forging risk, so:

- The hosted scan API blocks **link-local** (`169.254.0.0/16`, cloud metadata)
  and **RFC-1918** targets — a fail-closed SSRF guard that runs *before* any
  socket is opened.
- The hosted path scans **public** servers only; **stdio** targets are
  CLI-only (they may carry secrets and are never transmitted).
- Attacker-controlled finding text (from a hostile server) is stripped of
  terminal control bytes before it's printed to a TTY.
- Secrets live in `.env` (git-ignored); copy from `.env.example`.

---

## Repository layout

```
packages/
  engine/          # Apache-2.0 — detection engine (connect · enumerate · detect · score · report)
  cli/             # Apache-2.0 — `provenire` CLI
  control_plane/   # Proprietary — mapping · packs · evidence · scan API
docs/
  *-spec.md        # detection / cli / scan-api / mapping-pack / evidence specs (tests derive from these)
  references/      # pinned MCP 2025-06-18 security + authorization spec (cite, don't recall)
  dev-journal/     # STATUS.md (where we are) + per-feature logs
fixtures-servers/  # placeholder for adversarial fixture servers — wired up once the live transport adapter lands (today's tests use in-memory Session fakes)
infra/             # deployment scaffolding
```

---

## How it's built

Every line of production code is preceded by a failing test. Detection tests
derive from [`docs/detection-rules-spec.md`](docs/detection-rules-spec.md); pack
tests from [`docs/mapping-pack-spec.md`](docs/mapping-pack-spec.md). A behaviour
that isn't in a spec doesn't get built. See
[`CLAUDE.md`](CLAUDE.md) for the full engineering constitution and
[`docs/provenire-build-blueprint-v1.html`](docs/provenire-build-blueprint-v1.html)
for the workflow.

**Definition of done:** green tests + code review + security review + QA +
a human reads the diff.

---

## License

Provenire is **open-core** — there is no single license over the whole tree
(see [`LICENSE`](LICENSE) for the overview):

- `packages/engine`, `packages/cli` — **Apache-2.0**
  ([engine](packages/engine/LICENSE) · [cli](packages/cli/LICENSE)).
- `packages/control_plane` — **proprietary / commercial**
  ([license](packages/control_plane/LICENSE)); not covered by the open-source
  license. Contact tell2jyoti@gmail.com for commercial licensing.
