# Reference Index (pinned)

Canonical external docs for the build agents. **Pinned**, not live-fetched: the
two security-critical MCP pages are vendored locally (see files in this dir) so
reviews are deterministic and work offline. Everything else is listed by URL.

- Spec line pinned: **MCP 2025-06-18** (the current revision as of the retrieval
  date below). Do not silently bump — re-pinning is a deliberate, reviewed step.
- Retrieved / verified: **2026-06-28**.

## Vendored locally (offline, authoritative copy is the URL)

| File | Source | Revision |
| --- | --- | --- |
| `mcp-security-best-practices.md` | https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices | 2025-06-18 |
| `mcp-authorization.md` | https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization | 2025-06-18 |

## Indexed by URL (fetch on demand when re-pinning)

| Topic | URL | Used by |
| --- | --- | --- |
| MCP base protocol / lifecycle | https://modelcontextprotocol.io/specification/2025-06-18/basic | architect, F1 |
| MCP transports (stdio / streamable HTTP, session, resumability) | https://modelcontextprotocol.io/specification/2025-06-18/basic/transports | architect, security-reviewer, F1/F6/F7 |
| MCP server features (tools / resources / prompts) | https://modelcontextprotocol.io/specification/2025-06-18/server | architect, F1/F3 |
| MCP `llms.txt` (full doc map) | https://modelcontextprotocol.io/llms.txt | architect |
| RFC 9728 §7.7 (private-range blocking) | https://datatracker.ietf.org/doc/html/rfc9728#section-7.7 | security-reviewer, F7 |
| RFC 8707 (Resource Indicators) | https://www.rfc-editor.org/rfc/rfc8707.html | security-reviewer, F7 |
| OAuth 2.1 draft | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13 | security-reviewer, F7 |
| OWASP SSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html | security-reviewer, F7 |
| pytest | https://docs.pytest.org/en/stable/ | all, every feature |
| ruff | https://docs.astral.sh/ruff/ | code-reviewer |
| mypy | https://mypy.readthedocs.io/en/stable/ | code-reviewer |
| uv | https://docs.astral.sh/uv/ | all |
| pydantic v2 | https://docs.pydantic.dev/latest/ | architect, F3 (schema validation) |

## Re-pin procedure (deliberate, reviewed)

To refresh a vendored page when the spec advances:

1. WebFetch the source URL (see table) and read the new content.
2. Rewrite the matching local file, updating the provenance header
   (`Source`, `Revision`, `Retrieved`).
3. Update the pinned revision + retrieval date at the top of this file.
4. Re-run the affected detection/pack tests — a spec change may move a rule.
5. Record the re-pin as a one-line entry in `docs/dev-journal/STATUS.md`.

Vendored files are **condensations** of the normative text with provenance — the
URL is always authoritative. When in doubt, fetch the source.
