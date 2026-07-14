# A2A agent-card hardening fixture

A published A2A agent card (`/.well-known/agent-card.json`) with two v1.0-era
problems that are visible in the card itself, before any agent talks to it.

```bash
attestral scan examples/a2a-hardening
```

## What fires, and why

| Signal in the card | Rule | Risk |
|---|---|---|
| `securitySchemes` offers an OAuth2 `implicit` flow | ATL-129 | The implicit and password grants were removed in A2A 1.0 (they leak tokens in redirects / handle raw credentials); the card steers callers onto the withdrawn, weaker profile instead of authorization-code + PKCE. |
| Schemes defined, none required, and no `signatures[]` | ATL-130 | The agent is effectively public *and* its card is unsigned, so a peer cannot verify the card is authentic - anyone can stand up a look-alike endpoint with a matching card. |
| Schemes defined but no `security` requirement | ATL-123 | (Existing rule.) The card looks protected but requires no auth, so any external agent can invoke it. |

ATL-129 and ATL-130 are the additions: they read the card's *signing* and *OAuth
flow* structure, which the A2A 1.0 spec added and constrained.

## Research these checks are grounded in

- **A2A Protocol Specification 1.0** (Linux Foundation, 2026-03-12): section 8.4
  defines agent-card signing; v1.0.0 removed the OAuth2 implicit and password
  grant flows in favour of device-code + PKCE.
  <https://a2a-protocol.org/latest/specification/>
- **OWASP Top 10 for Agentic Applications 2026**: ASI07 Insecure Inter-Agent
  Communication, ASI03 Agent Identity & Privilege Abuse.
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
