# Detection Rules Spec

> Framework-neutral. Defines the `finding_type`s and the detection rules that
> produce them; this document is the source of the engine's tests. Every engine
> test cites a rule id here. Derived from TDD §07 (engine pipeline), §09 (data
> model), §10 (API) and the pinned MCP spec (`docs/references/`).
>
> **Architecture law:** rules emit `finding_type` only — never a regulation.
> Mapping lives in `control_plane/packs/*.yaml`. (CLAUDE.md.)
>
> Status: §1, §2, §3.1 filled (F1). §3.2+ filled per feature as we reach them.

## 1. Purpose & scope

The engine connects to a live MCP server, enumerates its primitives, normalizes
them, and runs deterministic detection over them, emitting scored,
framework-neutral `Finding` records. No LLM is used in the free engine
(deterministic by default — TDD §02).

In scope (Phase 1, engine): connect, enumerate, normalize, manifest hash (§3.1);
poisoning (§3.2); over-privilege & schema (§3.3); scoring (§4).
Out of scope here: target IP blocking / SSRF guard — that is a **request-layer**
concern on the **hosted** path (F7, TDD §11), not the engine. The CLI engine is
the sanctioned path for private/RFC-1918 and stdio servers (TDD §03, QA-T2), so
the engine itself does **not** block private targets.

## 2. Finding & manifest model

### 2.1 Normalized manifest (output of §3.1)
A `Manifest` is the normalized, deterministic snapshot of a scanned server:

- `ToolRecord`: `name` (str), `description` (str, "" if absent),
  `input_schema` (JSON object, `{}` if absent).
- `ResourceRecord`: `uri` (str), `name` (str), `description` (str).
- `PromptRecord`: `name` (str), `description` (str).
- `manifest_hash` (str): `"sha256:" + hex` over the canonical manifest (§3.1-R5).

Records are ordered canonically by a total order over their full content (not
just `name`/`uri`) so the manifest — and thus the hash — is independent of server
enumeration order, even for duplicate names (R5b). The manifest stores its record
sequences as immutable tuples so a built manifest's hash cannot drift from its
contents.

### 2.2 Finding (output of §3.2 onward)
Mirrors TDD §09 `finding`:

- `finding_type` (str): stable dotted id, e.g. `tool.poisoning`,
  `tool.over_privilege`. **Never** a regulation name.
- `entity_ref` (str): what it's about, e.g. `tool:send_mail`.
- `severity` (enum): `critical | high | medium | low`.
- `confidence` (float): `0.0–1.0`.
- `rationale` (str): one-line human explanation.

§3.1 (connect & enumerate) emits a `Manifest` and **no** `Finding`s — detection
`finding_type`s begin at §3.2.

## 3. Rules

### 3.1 Connect & enumerate  (feature F1, layer: engine)

Connection is mediated by a `Session` interface (the SDK `ClientSession` in
production; an in-memory fake in unit tests) exposing `initialize()`,
`list_tools()`, `list_resources()`, `list_prompts()`.

- **R1 — Handshake.** The engine calls `initialize()` before any enumeration. A
  scan that skips the handshake is invalid.
- **R2 — Timeout / unreachable.** `initialize()` (and each enumeration call) is
  bounded by a hard timeout (default **10s**, TDD §11). On timeout **or
  connection failure** (refused / DNS / reset — the target is unreachable) the
  engine raises `TargetUnreachable` (maps to API `408 target_unreachable`,
  TDD §10). It is an outcome, not a `Finding`.
- **R3 — Transport guard.** Transport is `streamable_http` or `stdio`. The
  engine accepts both; the **hosted** caller (F7) must reject `stdio` — the
  engine records the transport but does not itself forbid it (CLI needs stdio).
- **R4 — Enumerate all three.** The engine lists tools **and** resources **and**
  prompts. Omitting any of the three is a defect (deliberate coverage choice,
  TDD §07). An empty server yields an empty-but-present manifest of each.
- **R5 — Normalize + manifest hash.** Each primitive is normalized per §2.1.
  `manifest_hash` is a SHA-256 over a canonical JSON serialization of the sorted
  manifest (sorted keys, stable field order, no whitespace variance).
  - R5a — **Deterministic:** the same server scanned twice yields the same hash.
  - R5b — **Order-independent:** the hash does not depend on the order the
    server returned tools/resources/prompts. The canonical sort uses a **total
    order over the full record** (not just `name`/`uri`), so primitives that
    share a name/uri but differ in content still order deterministically — MCP
    does not guarantee unique names, and a hostile server must not be able to
    flip the hash by shuffling duplicates.
  - R5c — **Sensitive:** any change to **any field of any primitive kind**
    (tool `name`/`description`/`input_schema`; resource `uri`/`name`/
    `description`; prompt `name`/`description`) changes the hash (drift
    detection, TDD §07/§09).
- **R6 — Missing / malformed fields (engine never crashes on hostile input).**
  - Absent or `None` optional fields default: `description`/`name`/`uri` → `""`,
    `input_schema` → `{}`. Enumeration never raises on absent fields.
  - A **present** field of an unexpected type is **coerced, not dropped**:
    `name`/`uri`/`description` via `str(...)` (preserve the information so R5c
    stays sensitive); `input_schema` is kept only when it is a JSON object
    (`dict`), else `{}` (a non-object is not a schema).
  - A server returning a non-list (e.g. `None`) for an enumeration is treated as
    **empty** (R4 "empty-but-present").
  - The manifest hash tolerates JSON-incompatible values (e.g. non-serializable
    schema contents) without raising — a hostile server cannot crash the scan.
  - **Out of scope here (deferred, owner decision):** caps on primitive *count*
    and field *size*. The timeout (R2) bounds latency, not payload volume; a
    fast server can return a huge manifest within the window. Volume/size limits
    belong at the untrusted-transport boundary (SDK adapter / hosted F7, with
    TDD §11 "concurrency caps") and need owner-chosen thresholds — not invented
    in the engine.

Acceptance (F1): given a `Session` exposing a known set of primitives, the engine
returns a `Manifest` satisfying R4–R6, raising `TargetUnreachable` on R2, with a
hash meeting R5a–R5c. No `Finding`s are produced.

### 3.2 Poisoning detection  (feature F2, layer: engine)

Deterministic detection (no LLM) over the normalized `Manifest`'s text fields.
Tool descriptions are agent-facing instructions the model reads but the user
rarely sees, so they are a prime injection vector (MCP "tool poisoning";
`docs/references/mcp-security-best-practices.md`). The detector emits `Finding`s
(§2.2); it never names a regulation.

**Scanned surface.** For every primitive, the concatenated text of its
human/agent-facing fields — tools & prompts: `name` + `description`; resources:
`name` + `description`. `entity_ref` is `tool:<name>` / `prompt:<name>` /
`resource:<uri>`. All three kinds are scanned (consistent with R4).

**Determinism.** The same `Manifest` yields the same findings in a canonical
order: sorted by `(entity_ref, finding_type, first-match offset)`. At most one
finding per `(entity_ref, finding_type)` (the first/strongest match; rationale
names it).

**Provisional scoring.** Each rule below fixes a `severity` and `confidence`;
these are inputs to §4 (F4) which may normalize/suppress later. They are not
final assertions.

- **P1 — Invisible / non-printable Unicode → `tool.invisible_unicode`.**
  Flag any scanned text containing a character in these classes (used to hide
  instructions from a human reviewer while the model still reads them):
  - zero-width: U+200B, U+200C, U+200D, U+FEFF;
  - bidirectional controls: U+202A–U+202E, U+2066–U+2069;
  - Unicode Tags block: U+E0000–U+E007F;
  - any other Unicode `Cc` (control) or `Cf` (format) codepoint, **except** the
    ordinary whitespace `\t` (U+0009), `\n` (U+000A), `\r` (U+000D).
  Rationale names the offending codepoint(s) (e.g. `U+200B`). `severity: high`,
  `confidence: 0.95` (presence is unambiguous).

- **P2 — Hidden directive / instruction injection → `tool.poisoning`.**
  Flag text containing an imperative aimed at the *agent* rather than describing
  the tool. Canonical (case-insensitive) seed set — extensible as a constant,
  each new pattern needing a test:
  - `ignore (all |the )?(previous|prior|above) instructions`
  - `disregard .*instructions`
  - `do not (tell|inform|mention to|reveal to) the user`
  - `without (telling|informing|alerting) the user`
  - `system prompt`
  - injected directive blocks: `<important>…</important>`, `<system>…</system>`,
    `[system]…`
  Rationale quotes the matched phrase. `severity: high`, `confidence: 0.85`.

- **P3 — Exfiltration instruction → `tool.exfiltration`.**
  Flag text that pairs an **egress verb** (`send|forward|post|upload|exfiltrate|
  email|leak|transmit`) with **either** an external destination (`https?://…`,
  `ftp://…`, or an email address) **or** a sensitive-source token
  (`~/.ssh`, `id_rsa`, `\.env`, `api[_ ]?key`, `password`, `secret`,
  `credentials`, `access[_ ]?token`). Rationale names the verb + target.
  `severity: critical`, `confidence: 0.8`.

- **P0 — Clean text yields nothing.** A `Manifest` whose text contains none of
  the above produces **zero** `Finding`s (no false positives on ordinary tool
  descriptions). This is a first-class rule: the suite must prove benign,
  realistic descriptions stay silent.

Acceptance (F2): given a `Manifest`, the detector returns a deterministic,
canonically-ordered `list[Finding]` with the correct `finding_type`,
`entity_ref`, `severity`, `confidence`, and a rationale citing the match;
benign manifests yield `[]`; every rule P1–P3 has positive and negative tests.

### 3.3 Over-privilege & schema  (feature F3 — _to be filled when F3 starts_)

## 4. Scoring inputs  (feature F4 — _to be filled when F4 starts_)

## 5. Test fixtures

Unit tests use an in-memory `Session` fake constructed with explicit
tools/resources/prompts (no network, no SDK). Integration tests (marked `slow`)
will exercise the real MCP SDK adapter against fixture servers under
`fixtures-servers/` once the transport adapter lands.
