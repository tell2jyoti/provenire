# F<n> — <feature name>

> Copy to `F<n>-<slug>.md` when the feature starts. The orchestrator fills this
> in as the loop progresses; it is the durable record of *why*, not just *what*.
> Reviewers are read-only — their findings are pasted here by the orchestrator.

- **Layer:** engine | cli | control
- **Branch:** `feature/F<n>-<slug>`
- **Spec source:** docs/detection-rules-spec.md §… | docs/mapping-pack-spec.md §…
- **Started:** YYYY-MM-DD · **Done:** —

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (paste proof)
- [x] 3. Minimum code → **GREEN**
- [x] 4. Refactor; tests stay green (code already minimal — no refactor needed)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Findings fixed (test-first); re-reviews clean (code LOW-only addressed,
      security PASS, qa PASS)
- [ ] 7. Human read the diff → commit  ← **awaiting owner**

## 1. Architect design
Single public entrypoint `provenire_engine.scan(session, *, transport, timeout=10.0)`.
Data flow: `Session` (Protocol) → `connect.handshake` (R1/R2) → `enumerate.collect`
(R4, each call timeout-bounded) → `enumerate.normalize` (R6 defaults) →
`enumerate.manifest.build_manifest` (R5: canonical sort → sha256).

Modules: `connect/session.py` (Session Protocol + `Transport` literal),
`connect/errors.py` (`TargetUnreachable`), `connect/handshake.py` (`bounded` +
`handshake`), `enumerate/collect.py`, `enumerate/normalize.py`,
`enumerate/manifest.py` (frozen dataclasses + hash), `scan.py`.

Architect flags (spec silent → decided, not invented):
- **Async Session/scan** — mirrors the real `ClientSession`; tests drive via
  `asyncio.run`, no `pytest-asyncio`.
- **Transport excluded from the hash** — stdio vs http is the same server, not
  drift. Stored on `Manifest.transport` (un-hashed); pinned by a test.
- **R2 = translation test** — a `Session` call raising `TimeoutError` →
  `TargetUnreachable`; the literal 10s wall-clock is an integration concern.

## 2. Red proof
Before any source existed, `uv run pytest packages/engine/tests/unit -q`:
```
ERROR ... test_manifest_hash.py / test_normalize.py / test_scan.py
E   ModuleNotFoundError: No module named 'provenire_engine.enumerate.normalize'
E   ImportError: cannot import name 'scan' from 'provenire_engine'
!!! Interrupted: 3 errors during collection !!!
```
Legitimate red: the tests reference code that did not yet exist.

## 3 + 4. Green & refactor
Implemented the 7 modules above (core imports neither `control_plane` nor `mcp`).
Gates, all green:
- `uv run pytest packages/engine/tests/unit -q` → **20 passed**
- `uv run ruff check packages/engine` → clean
- `uv run mypy .` → **Success: no issues in 22 source files** (incl. tests, strict)

## 5 + 6. Review findings

Round 1 (all three reviewers, parallel). Strong convergence.

- **HIGH (code-rev + qa, proven) — R5b duplicate-name hash instability.** Sort
  key was `name` only; stable sort left duplicates in server order → hash flips
  on reorder (false drift). **Fixed:** `build_manifest` now sorts by full
  canonical content (`_canon(_tool_dict(t))`) → total order. Regression test
  `test_hash_order_independent_duplicate_tool_names`.
- **MED (security + code-rev + qa) — malformed/`None` server data crashed or was
  silently dropped.** **Fixed:** `_str` coerces present values (preserve, no
  crash), `_schema` keeps a dict only if JSON-serializable else `{}`, `_as_list`
  maps `None`/non-iterable → `[]`. Tests for non-str name/uri, non-dict schema,
  `None` lists.
- **MED (code-rev) — misleading `session.py` "needs no glue".** **Fixed:** docstring
  now states an adapter is required (SDK uses `inputSchema` / `ListToolsResult.tools`
  / `AnyUrl`).
- **LOW — frozen `Manifest` wrapped mutable lists.** **Fixed:** stores tuples.
- **LOW — `TargetUnreachable` only on timeout.** **Fixed:** `bounded` maps
  `OSError` (timeout + refused/reset/DNS) → `TargetUnreachable`; spec R2 broadened.
  Tests: real timeout bound (slow call) + `ConnectionRefusedError`.
- Coverage gaps (qa) — R5b/R5c for resources & prompts, nested-schema
  canonicalization: **closed** with new tests.

Round 2 (re-review of fixes): **code-reviewer** HIGH/MED none (4 LOW comment/
hardening notes), **security-reviewer** PASS (17-case hostile harness, no crash;
DoS deferral accepted), **qa** PASS (35 passed; all 5 gaps verified closed).

Final hardening pass (the converged LOW notes): `_str` made total (hostile
`__str__` can't crash — R6), `_canon` total (non-string keys/cycles can't crash
the hash layer), `except OSError` narrowed to `(TimeoutError, ConnectionError,
socket.gaierror)`, two over-claiming comments corrected. +6 tests.

Final gates: **41 passed**, ruff clean, `mypy .` strict clean (22 files).

### DEFERRED (owner decision — not invented)
- **Payload size/volume caps** (security MED): max primitive count, max field
  bytes. Needs owner-chosen thresholds; belongs at the untrusted-transport
  boundary (SDK adapter / hosted F7, TDD §11). Documented in spec §3.1 R6
  ("Out of scope here"). **OQ for owner before F7.**

## Decisions & open questions
- Spec gate: `detection-rules-spec.md` §1/§2/§3.1 were transcribed from the TDD
  (the file was a stub). Source of all F1 tests — owner should sanity-check.
- Engine does **not** block RFC-1918/private targets by design (CLI must reach
  them; blocking is the hosted F7 layer). Recorded in spec §1/§3.1-R3.
- Real MCP SDK adapter (`connect/mcp_adapter.py`) not yet written — F1 core is
  SDK-free; the adapter + integration fixtures land when transports are wired.

## Commit
_Hash + message once the human approves._
