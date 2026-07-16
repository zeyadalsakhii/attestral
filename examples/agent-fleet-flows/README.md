# agent-fleet-flows

Four MCP servers that are unremarkable one at a time, but whose *combination*
forms three architecture-level flows only the system model can see. No single
server is the finding; the crossing is.

Scan it:

```bash
attestral scan examples/agent-fleet-flows
```

| Flow | Rule | The crossing |
|---|---|---|
| Memory poisoning | ATL-214 | `web` ingests untrusted external content and `memory` is a persistent vector store, so attacker-controlled text can be written into long-term memory and steer the agent on future, unrelated sessions. |
| Covert tool invocation | ATL-215 | `assistant` declares the MCP `sampling` capability and is auto-approved, so a server-initiated model completion can drive tools with no human checkpoint (Unit 42, MCP sampling attack vectors, 2025). |
| Injection reaches cloud | ATL-216 | `web` ingests untrusted content and `cloud` holds AWS credentials in one agent, so an indirect prompt injection can drive cloud APIs with those keys - agent-to-cloud reachability with no public endpoint required. |

Each server also trips its own per-component checks (an auto-approved tool, a
persistent memory store, cloud credentials in env). The point of the fixture is
the fleet-level flows layered on top of them.
