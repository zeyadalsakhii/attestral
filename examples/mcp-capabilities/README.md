# MCP server-initiated capability fixture

Two servers declare protocol capabilities that hand *them* the initiative -
`sampling` (drive the user's model) and `elicitation` (prompt the user) - and one
plain filesystem server that declares neither. The point of the fixture is that a
declared capability is a design-time signal on its own: you can see it in the
config before the server ever runs.

```bash
attestral scan examples/mcp-capabilities
```

## What fires, and why

| Server | Rule | Risk |
|---|---|---|
| `assistant-bridge` | ATL-125 | Declares `sampling`: can spend the user's model tokens on hidden tasks, keep injected text alive across turns, and steer the model into tool calls the user never approved (Unit 42, 2025-12). |
| `intake` | ATL-126 | Declares `elicitation`: can put free-form prompts in front of the user mid-task, phrased to extract data the tool never legitimately needs ("When MCP Servers Attack", 2025-09). |
| `readonly-notes` | *(none of these)* | Declares no server-initiated capability: the capability rules deliberately stay silent, so absence never fires. |

`sampling` and `elicitation` are server-*initiated* channels the model cannot
police from inside the dialog, which is why they are worth flagging at design
time rather than only watching at runtime.

## Research these checks are grounded in

- **Unit 42, "Model Context Protocol (MCP) attack vectors"** (2025-12-05):
  resource theft, conversation hijacking, and covert tool invocation via a
  server's `sampling/createMessage` requests.
  <https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>
- **"When MCP Servers Attack: Taxonomy, Feasibility, Mitigation"**
  (arXiv 2509.24272): elicitation abuse and sampling abuse as named classes.
  <https://arxiv.org/abs/2509.24272>
- **OWASP Top 10 for Agentic Applications 2026**: ASI02 Tool Misuse &
  Exploitation, ASI09 Human-Agent Trust Exploitation.
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **OWASP MCP Top 10** (pilot): MCP06 Intent Flow Subversion, MCP10 Context
  Injection & Over-Sharing. <https://owasp.org/www-project-mcp-top-10/>
