# MCP — Security Best Practices (pinned condensation)

> **Source:** https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
> **Revision:** 2025-06-18 · **Retrieved:** 2026-06-28
> Condensation of the normative text — the URL is authoritative. Re-pin per
> `docs/references/INDEX.md`. Read alongside `mcp-authorization.md`.

This is the single most relevant external reference for Provenire: it names the
exact threats the engine detects and the SSRF rules `CLAUDE.md` mandates.

## Attacks & mitigations

### Confused deputy (OAuth proxy)
Proxy servers using a **static client ID** to a third-party AS, while allowing
**dynamic client registration** and relying on a third-party **consent cookie**,
can leak MCP authorization codes to an attacker `redirect_uri`.
- MCP proxy servers **MUST** implement per-client consent *before* forwarding to
  the third-party AS; check a per-user registry of approved `client_id`s first.
- Consent page **MUST** name the client, show requested scopes + registered
  `redirect_uri`, add CSRF protection, and block iframing (`frame-ancestors` /
  `X-Frame-Options: DENY`).
- Consent cookies **MUST** use `__Host-` prefix, `Secure`/`HttpOnly`/`SameSite=Lax`,
  be signed/server-side, and bind to a specific `client_id`.
- `redirect_uri` **MUST** be validated by exact string match against the
  registered value (no wildcards).
- OAuth `state` **MUST** be cryptographically random, single-use, short-lived,
  stored server-side **only after** consent, and matched exactly at callback.

### Token passthrough (anti-pattern, forbidden)
An MCP server accepting tokens not issued *to it* and forwarding them downstream
circumvents security controls, breaks audit trails, and crosses trust boundaries.
- MCP servers **MUST NOT** accept any token not explicitly issued for the server.

### Server-Side Request Forgery (SSRF) — **core to Provenire**
A malicious MCP server can populate OAuth-discovery URLs (`resource_metadata`,
`authorization_servers`, `token_endpoint`, …) pointing at internal resources.
Attack targets: internal IPs (`192.168.x`, `10.x`), **cloud metadata
`169.254.169.254`**, localhost services, DNS rebinding, redirect chains.
- Clients deployed server-side **MUST** consider SSRF and mitigate when fetching
  OAuth URLs.
- **SHOULD** require HTTPS for OAuth URLs (allow `http` only for loopback in dev).
- **SHOULD** block private/reserved ranges per RFC 9728 §7.7:
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`,
  **`169.254.0.0/16` (incl. cloud metadata)**, `fc00::/7`, `fe80::/10`.
- **Do not hand-roll IP validation** — attackers use octal/hex/IPv4-mapped-IPv6
  encodings custom parsers miss. Prefer a vetted library / egress proxy.
- Validate redirect targets the same way; beware TOCTOU DNS rebinding (pin DNS
  between check and use; defense in depth).
- → Provenire mapping: this is the basis of `CLAUDE.md`'s "block link-local
  (169.254.0.0/16) & RFC-1918 targets" rule and feature **F7** (Scan API + SSRF
  guard, `blocked_target`).

### Session hijacking
Stateful HTTP servers sharing session IDs are open to prompt-injection via a
shared event queue and to impersonation.
- Servers implementing auth **MUST** verify all inbound requests and **MUST NOT**
  use sessions for authentication.
- Session IDs **MUST** be secure, non-deterministic (CSPRNG, e.g. UUIDs); avoid
  sequential IDs; rotate/expire.
- **SHOULD** bind session IDs to user info, e.g. key `<user_id>:<session_id>`,
  so a guessed session ID can't impersonate another user.

### Local MCP server compromise
Locally executed servers can carry malicious startup commands / payloads (data
exfiltration, privilege escalation, DNS-rebinding to localhost).
- One-click local-server config **MUST** show the exact command (untruncated),
  flag it as dangerous, and require explicit approval.
- **SHOULD** highlight dangerous patterns (`sudo`, `rm -rf`, network/FS access),
  sandbox spawned servers with least privilege.
- Servers meant to run locally **SHOULD** use `stdio` to limit access; if HTTP,
  require an auth token or restricted IPC (unix sockets).
- → Provenire mapping: aligns with `CLAUDE.md` "stdio = CLI only".

### OAuth authorization-URL validation (XSS / RCE)
Malicious servers can return `javascript:`/`data:`/`file:` authorization URLs or
shell-injection payloads.
- Clients **MUST** allow only `http://`(loopback dev)/`https://` schemes; reject
  `javascript:`, `data:`, `file:`, `vbscript:` (allowlist, not blocklist).
- **MUST NOT** open URLs via a shell; use non-shell platform openers.
- Web clients **SHOULD** apply CSP (`script-src 'self'`), sanitize all URLs.

### stdio transport in proxy scenarios
Only applies to proxy architectures spawning servers as child processes: XSS →
stolen proxy token → arbitrary `stdio` command execution.
- Mitigate the OAuth-URL XSS class; sandbox/log spawned processes; least
  privilege for the proxy itself.

### Scope minimization
Broad up-front scopes (`files:*`, `admin:*`, `*`) inflate compromise blast
radius and consent churn.
- Use progressive least-privilege scopes; minimal baseline (e.g.
  `mcp:tools-basic`); elevate via targeted `WWW-Authenticate scope="..."`.
- Servers **SHOULD** emit precise scope challenges, not the full catalog; accept
  down-scoped tokens.
- Common mistakes: publishing all scopes in `scopes_supported`; wildcard/omnibus
  scopes; trusting claimed token scopes without server-side authz.
