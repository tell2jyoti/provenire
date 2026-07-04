# Scan API spec — F7 (`control_plane`, COMMERCIAL)

> Distilled from **TDD §10** (API specification) and **TDD §11** (Security
> architecture). This is the citable working spec; the TDD HTML is the ultimate
> source. Tests derive from the numbered rules here (test-first law, CLAUDE.md).
>
> **Layer:** `control_plane` (proprietary). Engine and CLI must **never** import
> control_plane (architecture law). control_plane *may* import `attestable_engine`.
>
> **Scope of F7 (this loop trip):** `POST /scan` only — synchronous scan + SSRF
> guard + rate limit. **No persistence.** `GET /scan/{id}`, report retrieval,
> evidence, reputation, and monitors are later features (§7).

## §1 Scope & boundaries

- **A0 — Reuse, don't reinvent.** The API reuses the engine's F1→F5 pipeline
  exactly as the CLI does: `connect` → `scan` → `detect_poisoning` +
  `detect_over_privilege` → `score_findings` → `build_report`. The API adds only
  what the engine deliberately omits: the **SSRF guard** (§4), **rate limiting**
  (§6), and HTTP shaping. The engine stays framework-neutral and names no
  regulation; the API adds no detection logic.
- **A0.1 — Injected transport seam** (mirrors cli-spec §1). The live MCP
  transport adapter is a later integration slice, so the connection is an
  **injected** `connect` factory; unit tests supply an in-memory fake `Session`.
  The default factory is a stub that raises `TargetUnreachable` until the
  transport slice lands (C6). SSRF validation runs **before** `connect` is ever
  called, so it is fully testable now without a live socket.
- **A0.2 — Framework.** FastAPI (TDD §03: "Scanner API — FastAPI"). Tests drive
  the app in-process via Starlette `TestClient` (httpx) — no live port.
- **A0.3 — Data boundary** (TDD §11, FR-05, NFR-02). The hosted API scans
  **public servers only**. stdio / private / regulated servers use the CLI /
  self-host path so manifests never leave the customer's network. Therefore the
  API accepts **`transport: "streamable_http"` only**; `stdio` is rejected
  (§2/A4).

## §2 `POST /scan` — request contract

- **A1 — Path & method.** `POST /scan`. Content-Type `application/json`.
- **A2 — Body fields.** `{"target": <url>, "transport": "streamable_http",
  "mode": "deterministic"}`.
- **A3 — `target` required, must be a valid absolute `http`/`https` URL with a
  host.** Missing/blank/non-URL/relative → `400 invalid_target` (§5).
- **A4 — `transport` optional, default `"streamable_http"`; only
  `"streamable_http"` is accepted.** Any other value (incl. `"stdio"`) →
  `400 invalid_target` (A0.3 — stdio is CLI-only).
- **A5 — `mode` optional, default `"deterministic"`.** `"semantic"` is a paid,
  opt-in tier not in the free hosted path → `402 tier_required` (§5). Any other
  value → `400 invalid_target`.

## §3 `POST /scan` — success response (200)

Synchronous, target < 10s (§4/S5). Body:

```json
{
  "scan_id": "scn_<token>",
  "server_hash": "sha256:…",
  "summary": { "critical": 1, "high": 2, "medium": 0, "low": 0, "gate": "fail" },
  "findings": [
    { "id": "f1", "type": "tool_poisoning", "severity": "critical",
      "confidence": 0.92, "entity": "tool:send_mail",
      "rationale": "hidden directive in description" }
  ],
  "report_url": null
}
```

- **A6 — `server_hash`** is the engine `Manifest.manifest_hash` verbatim
  (`"sha256:…"`).
- **A7 — `summary`** derives from the engine `ScanScore`: the four severity
  counts (`critical`/`high`/`medium`/`low`) plus `gate` (`"pass"`|`"fail"`).
  *(Deferral: the TDD example shows a `"pass":N` count of clean entities; the
  engine `ScanScore` does not compute one. Out of scope this trip — see OQ-1.)*
- **A8 — `findings`** is the risk-ordered `ScanResult.findings`, each mapped
  field-for-field: `type`←`finding_type`, `entity`←`entity_ref`, plus
  `severity`, `confidence`, `rationale`. `id` is a stable per-response index
  (`f1`, `f2`, …) in the engine's risk order.
- **A9 — `scan_id`** is a generated opaque token (`scn_` + hex). *(Deferral:
  with no persistence it is informational only — nothing can be fetched by it
  until the store lands. See OQ-2.)*
- **A10 — `report_url` is `null` this trip.** Report retrieval / S3 hosting is a
  later feature (§7). The rendered report is not lost — it is produced by
  `build_report`; it is simply not yet addressable by URL.
- **A11 — Determinism** (NFR-03). Given the same manifest, `summary` and
  `findings` are byte-identical across runs. `scan_id` is the only nondetero
  field and never feeds the report.

## §4 SSRF guard — **P0** (TDD §11, the reason this API exists)

> A service that connects to user-supplied URLs is an SSRF weapon if unguarded
> (aim it at cloud metadata or internal hosts). The engine deliberately omits
> this (detection-rules-spec §1); it lives **here**. P0, ships in v1.

- **S1 — Block link-local `169.254.0.0/16`** (includes the `169.254.169.254`
  cloud-metadata endpoint). `403 blocked_target`.
- **S2 — Block loopback** (`127.0.0.0/8`, `::1`). `403 blocked_target`.
- **S3 — Block RFC-1918 private ranges** (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`) and their IPv6 equivalents (unique-local `fc00::/7`,
  link-local `fe80::/10`). `403 blocked_target`.
- **S3.1 — Block other non-public ranges** a metadata/internal pivot could use:
  unspecified (`0.0.0.0/8`, `::`), reserved/multicast, and IPv4-mapped IPv6
  (`::ffff:0:0/96`, so a mapped `169.254.169.254` cannot slip through). Decide
  membership by classifying the resolved IP as **not globally routable**, not by
  a hand-maintained allowlist of strings.
- **S4 — Re-resolve DNS and re-check to defeat rebinding.** Validation must
  operate on the **resolved IP address(es)**, not the hostname string. If a host
  resolves to *any* blocked address, block. The resolved-and-vetted address is
  what the scan connects to (a later live-transport concern; this trip validates
  every resolved IP and blocks if any is non-public). A literal-IP target is
  classified directly.
- **S5 — Hard timeout.** ≤ 10s per scan (TDD §11, §10 "synchronous, <10s"). A
  slow/malicious target cannot exhaust the box. Enforced around the pipeline;
  timeout → `408 target_unreachable`.
- **S6 — Validate before connect.** SSRF checks run **before** the `connect`
  factory is invoked. A blocked target never opens a socket.
- **S6.1 — Fail closed.** If the target cannot be resolved/classified at all,
  reject — never fall through to a scan. (Unresolvable host → `400
  invalid_target`; resolves only to blocked IPs → `403 blocked_target`.)

*Infra-layer defences (NOT app code, out of scope for F7 — recorded so a future
reader knows where they live): egress filtering to public-only, IMDSv2 hop-limit
1, least-privilege IAM, secrets in SSM (TDD §11, §05). These are deployment
controls, not Python.*

## §5 Error model & status codes (TDD §10)

Body shape: `{"error": {"code": "<code>", "message": "<human msg>"}}`.

- **E1 — `400 invalid_target`** — malformed/missing target, disallowed
  transport/mode value (A3/A4/A5), or unresolvable host (S6.1).
- **E2 — `403 blocked_target`** — target resolves to a private/metadata/
  non-public IP (§4).
- **E3 — `408 target_unreachable`** — handshake/scan timed out or the target
  refused connection (engine `TargetUnreachable`, S5).
- **E4 — `429 rate_limited`** — free-tier rate limit exceeded (§6).
- **E5 — `402 tier_required`** — a paid-tier feature was requested on the free
  path (`mode: "semantic"`, A5).
- **E6 — Messages are safe.** Error `message` must not echo attacker-controlled
  target bytes raw (control chars stripped, mirroring cli `_safe`); it must not
  leak internal IPs the resolver returned.

## §6 Rate limiting (TDD §10, free tier)

- **R1 — Per-IP limit** on `POST /scan`: default **30 scans / hour / IP**
  (configurable). Over the limit → `429 rate_limited` (E4). The per-IP key is the
  **authenticated peer address**, never the client-supplied `X-Forwarded-For`
  header (spoofable → an attacker rotates it to mint unlimited quota). `X-Forwarded-For`
  is honoured **only** when the app is configured behind a trusted proxy
  (`create_app(trust_forwarded_for=True)`, default off); a blank hop falls through
  to the peer. Added after F7 security review (see F7 log §5).
- **R2 — `X-RateLimit-*` headers** on responses: `X-RateLimit-Limit`,
  `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
- **R3 — In-memory limiter** this trip (single instance, TDD §03: one EC2 box).
  A shared/distributed store is deferred with persistence (§7). The limiter must
  be injectable so tests control the clock/counter deterministically (no wall
  clock in the pure logic).

## §7 Deferred — explicitly out of scope for F7

Recorded so scope creep is visible and the next feature knows where to pick up:

- `GET /scan/{id}` and `GET /scan/{id}/report` — need a persistence store
  (Neon Postgres + S3 per TDD §03/§05). → later feature.
- `POST /scan/{id}/evidence` — Compliance tier; depends on F8/F9 mapping. →
  F8/F9.
- `GET /servers/{hash}/reputation`, `POST /monitors`, `GET /monitors/{id}/events`
  — Team+ tiers. → later.
- `mode: "semantic"` execution — paid model layer. F7 only *rejects* it (E5).
- Auth (`Authorization: Bearer <api_key>`) — account endpoints only; the free
  `POST /scan` is anonymous. → when account endpoints land.
- Infra SSRF controls (egress filter, IMDSv2, IAM) — deployment, not app code.

## §8 Open questions (owner)

- **OQ-1** — `summary.pass` count of clean entities: compute in the API (manifest
  entity count − flagged) or add to the engine `ScanScore`? Deferred; F7 omits it.
- **OQ-2** — `scan_id` scheme once persistence lands: random token vs derived
  from `server_hash` + timestamp. F7 uses an opaque random token, informational.
- **OQ-3** — DNS re-resolution vs the eventual live transport: F7 validates all
  resolved IPs at request time; binding the *connection* to the vetted IP
  (full anti-rebinding) is completed when the real streamable_http adapter lands.
