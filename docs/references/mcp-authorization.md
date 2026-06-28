# MCP — Authorization (pinned condensation)

> **Source:** https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
> **Revision:** 2025-06-18 · **Retrieved:** 2026-06-28
> Condensation of the normative text — the URL is authoritative. Re-pin per
> `docs/references/INDEX.md`. Read alongside `mcp-security-best-practices.md`.

Relevant to Attestable's control-plane scan API (**F7**) and to the
security-reviewer when judging auth handling.

## Scope
- Authorization is **OPTIONAL**; it applies to **HTTP-based transports**.
- **stdio** transport **SHOULD NOT** use this flow — retrieve credentials from
  the environment instead. (Reinforces `CLAUDE.md` "stdio = CLI only".)
- Built on a subset of: OAuth 2.1 (draft-ietf-oauth-v2-1-13), RFC 8414 (AS
  Metadata), RFC 7591 (Dynamic Client Registration), RFC 9728 (Protected
  Resource Metadata).

## Discovery & flow
- Authorization servers **MUST** implement OAuth 2.1 for confidential + public
  clients.
- MCP servers **MUST** implement RFC 9728 Protected Resource Metadata; clients
  **MUST** use it for AS discovery.
- AS **MUST** provide RFC 8414 AS Metadata; clients **MUST** use it.
- On 401, servers **MUST** send `WWW-Authenticate` pointing to the resource
  metadata URL; clients **MUST** parse it and respond.
- Dynamic Client Registration (RFC 7591): clients + AS **SHOULD** support it.

## Resource parameter (RFC 8707) — audience binding
- Clients **MUST** include `resource` in **both** authorization and token
  requests, identifying the MCP server by its **canonical URI** (scheme+host,
  no fragment; prefer no trailing slash). **MUST** send it even if the AS doesn't
  support it.

## Token usage & validation
- Clients **MUST** send `Authorization: Bearer <token>` on **every** request;
  tokens **MUST NOT** appear in the URI query string.
- Servers (as OAuth 2.1 resource server) **MUST** validate tokens were issued
  **specifically for them** (audience, RFC 8707 §2); invalid/expired → **401**.
- Clients **MUST NOT** send tokens other than those issued by the MCP server's
  own AS. Servers **MUST NOT** accept or transit any other tokens.
- If the server calls upstream APIs, it acts as a separate OAuth client and
  **MUST NOT** pass through the client's token (see token passthrough in
  `mcp-security-best-practices.md`).

## Error codes
| Code | Meaning |
| --- | --- |
| 401 | Auth required / token invalid |
| 403 | Invalid scopes / insufficient permissions |
| 400 | Malformed authorization request |

## Security requirements (normative highlights)
- **PKCE** — clients **MUST** implement it (OAuth 2.1 §7.5.2).
- **Communication** — all AS endpoints **MUST** be HTTPS; redirect URIs **MUST**
  be `localhost` or HTTPS.
- **Open redirect** — clients **MUST** pre-register redirect URIs; AS **MUST**
  exact-match them; clients **SHOULD** use + verify `state`.
- **Token theft** — secure storage required; AS **SHOULD** issue short-lived
  tokens and **MUST** rotate refresh tokens for public clients.
- **Confused deputy** — proxy servers with static client IDs **MUST** get user
  consent per dynamically registered client before forwarding.
- **Audience restriction** — servers **MUST** reject tokens not in their audience
  claim; **MUST NOT** pass tokens through to upstream APIs.
