# F7 — Scan API + SSRF guard

> Durable record of *why*, not just *what*. Reviewers are read-only — the
> orchestrator pastes their findings here.

- **Layer:** control (first `control_plane` / COMMERCIAL feature)
- **Branch:** `chore/agent-context-setup` (F1–F6 all landed here)
- **Spec source:** `docs/scan-api-spec.md` (distilled from TDD §10 + §11)
- **Started:** 2026-07-04 · **Done:** 2026-07-04 (`8e53fc5`)

## Loop progress (blueprint §06)

- [x] 1. Architect — design + ordered TEST LIST + acceptance criteria
- [x] 2. Tests written first, run, **shown RED** (paste proof)
- [x] 3. Minimum code → **GREEN** (2026-07-04)
- [x] 4. Refactor; tests stay green (nothing needed — clean at green)
- [x] 5. code-reviewer + security-reviewer + qa run on the diff
- [x] 6. Every finding fixed; reviews re-run clean (sec HIGH closed; code 4/4; qa PASS)
- [x] 7. Human read the diff → commit (`8e53fc5`, 2026-07-04)

## Kickoff decisions (owner, 2026-07-04)

Asked before spawning the architect because they change what gets built:

1. **Scope:** `POST /scan` only — synchronous scan + SSRF guard + rate limit,
   **no persistence**. `GET /scan/{id}` + report retrieval need a Postgres/S3
   store → deferred (scan-api-spec §7). Matches STATUS backlog.
2. **Framework:** FastAPI + Starlette `TestClient` (httpx). TDD §03 names
   FastAPI; adding `fastapi` + `httpx` to control_plane deps.
3. **Spec artifact:** wrote `docs/scan-api-spec.md` first (distilled TDD §10/§11)
   so tests cite numbered rules — matches the cli-spec.md pattern for F6.

**Architecture-law watch:** control_plane may import `provenire_engine`; engine
and cli must never import control_plane. The SSRF guard the engine deliberately
omits (detection-rules-spec §1) lives here.

## 1. Architect design (2026-07-04)

### Modules (`packages/control_plane/src/provenire_control_plane/api/`)
- `models.py` — Pydantic `ScanRequest` (target, transport default `streamable_http`, mode default `deterministic`), `ScanResponse`, `ErrorResponse`.
- `ssrf.py` — **the P0.** `IPClassifier` (globally-routable vs blocked, via `ipaddress` stdlib; S1–S3.1 incl. IPv4-mapped IPv6), `resolve_target(host, resolver)`, `validate_ssrf(url, resolver)` → raises `BlockedTarget`/`InvalidTarget`. Resolver injected (no real DNS in tests).
- `rate_limit.py` — `RateLimiter` ABC + `InMemoryRateLimiter(limit=30, window=3600, clock=time.time)`; `check_and_record(ip) -> (remaining, limit, reset)`; clock injectable.
- `errors.py` — exception classes → HTTP code + error-code string; `safe_message()` mirrors CLI `_safe()` (strip C0/C1/DEL, no IP leak).
- `handlers.py` — `POST /scan` orchestrator: validate body → validate URL → transport/mode → SSRF (resolve+classify) → rate-limit → connect(injected) → engine pipeline → shape 200 + rate headers.
- `app.py` — FastAPI app factory; accepts injected `connect`, `resolver`, `rate_limiter`.

### Request flow
body(Pydantic A1/A2) → target abs http/https+host (A3) → transport (A4) → mode (A5, semantic→402) → SSRF resolve (S4, unresolvable→400) → classify all IPs, any blocked→403 (S1–S3.1/S6.1) → rate-limit (R1) → **connect (S6: SSRF runs first)** → scan→detect→score→build_report → 200 {scan_id, server_hash, summary, findings[f1..], report_url:null} + `X-RateLimit-*` (R2).

### Error mapping (§5)
400 invalid_target (E1: bad target / bad transport-mode / unresolvable) · 403 blocked_target (E2) · 408 target_unreachable (E3: timeout/refused/engine `TargetUnreachable`) · 429 rate_limited (E4) · 402 tier_required (E5: semantic). Body `{"error":{"code","message"}}`, message safe (E6).

### Ordered TEST LIST (75) — `packages/control_plane/tests/test_api.py`
Written red in this order:
- **A. SSRF unit (1–19)** — classify blocked: metadata 169.254.169.254 (S1), link-local range (S1), loopback 127.0.0.1 / 127.255.255.255 / ::1 (S2), RFC-1918 10/8, 172.16/12, 192.168/16 (S3), IPv6 fc00::/7, fe80::/10 (S3), unspecified 0.0.0.0 / :: (S3.1), IPv4-mapped `::ffff:169.254.169.254` (S3.1); allow public 8.8.8.8, 1.1.1.1, 2001:4860:4860::8888 (S3.1 contra); unresolvable→InvalidTarget (S6.1); all-blocked→BlockedTarget (S4/S6.1); any-blocked→BlockedTarget fail-closed (S4).
- **B. Request validation (20–36)** — POST-only/405 & path/404 (A1), JSON CT (A2), target missing/blank/not-url/relative/ftp/no-host →400 (A3), transport missing-default/streamable_http-ok/stdio-reject/unknown-reject (A4), mode missing-default/deterministic-ok/semantic→402/unknown→400 (A5/E5).
- **C. SSRF+HTTP (37–47)** — 403 for metadata/loopback/rfc1918-10/172/192/ipv6-ula/ipv6-ll/mapped-ipv6 (S1–S3.1/E2), rebinding any-blocked→403 (S4), unresolvable→400 (S6.1/E1), **connect-not-called-when-blocked (S6)**.
- **D. Success shaping (48–55)** — server_hash=manifest_hash (A6), summary counts+gate (A7), findings mapped id/type/entity/severity/confidence/rationale (A8), stable indices + risk order (A8), scan_id `scn_<hex>` (A9), report_url null (A10), determinism same-manifest byte-identical (A11).
- **E. Error bodies (56–63)** — each code's `{error:{code,message}}` shape (E1–E5), message strips control chars (E6), no resolved-IP leak (E6), engine `TargetUnreachable`→408 (E3).
- **F. Timeout (64–66)** — 10s cap, exceed→408, wraps whole pipeline (S5/E3).
- **G. Rate limit (67–75)** — 30/hr default (R1), enforced-per-IP 31st→429 (R1), configurable (R1), independent per-IP windows (R1), `X-RateLimit-*` present on 200+429 (R2), limit-header value (R2), remaining decrements ≥0 (R2), reset=unix-ts (R2), injectable clock (R3).

### Acceptance criteria
All 75 red-before-green; 6 modules implemented; `uv run pytest -q` clean; ruff + mypy --strict clean; **architecture law** (control_plane→engine ok; engine/cli never →control_plane; no regulation named); SSRF blocks S1–S3.1 + fails closed + runs before connect; rate limit 30/hr + headers + injectable clock; determinism (scan_id only nondeterministic field); error messages safe + no IP leak; reviewers + qa PASS; human-approved commit.

### Spec gaps (deferred, none block the test list)
OQ-1 `summary.pass` count (engine has no entity count) — omitted. OQ-2 `scan_id` scheme — random opaque token for now. OQ-3 full anti-rebinding — completed with live transport adapter (C6 stub today). All 75 tests derive from A1–A11/S1–S6.1/E1–E6/R1–R3 as written.

### New dependency
`packages/control_plane/pyproject.toml`: add `fastapi` + `httpx` (TestClient).

## 2. Red proof

75 tests written in `packages/control_plane/tests/test_api.py` before any
production code. First run — the `api/` modules do not exist, so collection
fails (canonical "no code yet" red):

```
ERROR collecting packages/control_plane/tests/test_api.py
  packages/control_plane/tests/test_api.py:22: in <module>
      from provenire_control_plane.api.app import create_app
  E   ModuleNotFoundError: No module named 'provenire_control_plane.api.app'
!!! Interrupted: 1 error during collection !!!
```

Deps added first: `fastapi>=0.110` (control_plane runtime), `httpx>=0.27` (root
dev, for TestClient). `uv sync` → fastapi 0.139, starlette 1.3.1, httpx 0.28.

## 3 + 4. Green & refactor

Implemented the 3 modules the architect designed on top of the 3 already-written
guards (ssrf/rate_limit/errors):
- `models.py` — Pydantic `ScanRequest` (lenient) + response models (`Summary`,
  `FindingModel`, `ScanResponse`, `ErrorResponse`). Request is policed in the
  handler, not by Pydantic, so transport/mode drive 400 vs 402 (not a blanket 422).
- `handlers.py` — `handle_scan`: parse body (A1/A2) → target (A3) → transport
  (A4) → mode (A5, semantic→402) → **SSRF resolve+classify before any socket
  (S1-S6.1)** → rate-limit (R1) → engine F1→F5 pipeline under one
  `asyncio.wait_for(timeout)` (S5) → shape 200 + `X-RateLimit-*` (A6-A11/R2).
  Reuses `provenire_engine` unchanged (same pipeline the CLI drives). Engine
  `TargetUnreachable`/`TimeoutError` → api `TargetUnreachable` 408 with a fixed,
  secret-free message (E6). Findings `entity`/`rationale` run through
  `safe_message` (hostile-server text).
- `app.py` — `create_app(*, connect, resolver, rate_limiter=None, timeout=10.0)`;
  registers a single `ApiError` exception handler rendering
  `{"error":{"code","message"}}` (safe), and attaching `X-RateLimit-*` on 429.

**Final run:** `uv run pytest -q` → **363 passed** (288 at F6 + 75 F7). ruff
clean; `uv run mypy .` --strict clean. No refactor needed — green code was
already lint/type clean.

**One test corrected (owner-approved):** `test_slow_scan_times_out_408` wired
`sleep=1.0` onto an inner `_FakeSession` passed *as a tool* (never awaited), so
the scan never delayed and returned 200 — the test could not exercise its own S5
intent. Fixed to `_connect(_CLEAN_TOOL, sleep=1.0)` so the returned session's
`list_tools()` sleeps 1.0s vs `timeout=0.02` → 408, matching the passing sibling
`test_slow_connect_times_out_408`. Human approved the edit before it was made.

## 5 + 6. Review findings

Three reviewers ran on the diff in parallel; findings fixed in one pass, then the
security + code reviewers re-verified.

**security-reviewer — 1 HIGH (fixed), 1 LOW (false positive).**
- **HIGH — X-Forwarded-For rate-limit bypass** (`handlers.py` `_client_ip`). XFF is
  client-supplied and spoofable; keying the limiter on it let an attacker rotate
  the header to mint a fresh 30/hr window per value. **Owner decision:** trust XFF
  only behind a configured proxy — `create_app(trust_forwarded_for=True)`, default
  **off** (keys on the peer address). Blank hop falls through to the peer. Threaded
  through `handle_scan`/`create_app`; spec §6/R1 updated. New regression test
  `test_forwarded_for_untrusted_by_default` (rotating XFF → 2nd request 429);
  `test_independent_per_ip` opts into the proxy case. **Re-verified: HIGH CLOSED.**
- LOW — claimed a `X-RateLimit-For` docstring typo; the code read `x-forwarded-for`.
  False positive (misread); docstring since expanded with the trust rationale.
- All SSRF (S1-S6.1), E6 info-leak, S5 timeout, determinism, and architecture-law
  checks passed clean on the first pass.

**code-reviewer — 4 findings, all fixed** (`handlers.py`): (1) `_shape(result: object)`
+ two `type: ignore` → typed `result: ScanResult` (engine export), ignores removed,
mypy --strict still clean; (2) dead `_SEVERITIES` constant deleted; (3) unused
`_report_json` → `_`; (4) blank/whitespace XFF edge — folded into the trust-flag fix.

**qa — PASS.** All 30 spec rules (A1-A11, S1-S6.1, E1-E6, R1-R3) have substantive,
non-tautological coverage; red-before-green proven (collection error in §2); S5
whole-pipeline timeout validated; no skips/xfails; architecture law enforced.

**Final:** `uv run pytest -q` → **364 passed** (75 F7 + 1 new spoof-guard test on
top of F6's 288); ruff + `uv run mypy .` --strict clean.

## Decisions & open questions
_See scan-api-spec §8 (OQ-1 pass-count, OQ-2 scan_id scheme, OQ-3 anti-rebinding
completion with the live transport). Link ADRs for architectural calls._

## Commit

`8e53fc5` — feat(control): F7 scan API + SSRF guard — POST /scan, blocked_target
on metadata/RFC-1918/link-local, per-IP rate limit. Human-approved 2026-07-04.
Suite 364 passed; ruff + mypy --strict clean. STATUS flip in the follow-up chore.
