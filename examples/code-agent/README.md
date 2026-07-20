# Code-defined agent fixture (M11)

Most agents are wired in Python, not `.mcp.json`. This fixture is a LangGraph
agent whose three tools are plain `@tool` functions - there is no config file
for a config-only scanner to read. Attestral AST-parses the code, models the
file as a `code_agent` surface, and reads each tool's capability from the
symbols its body uses (`requests` -> network, `subprocess` -> shell).

```bash
attestral scan examples/code-agent
```

```
1 component · 4 findings · 4 high

Attack paths (1)
  internal chain:
    entry: untrusted input ingested by a tool  [agent]
    pivot: code execution  [agent]
    impact: exfiltration  [agent]
```

| Rule | Severity | Why it fires |
|---|---|---|
| ATL-139 | high | The code-defined agent grants a shell/command-execution tool (`run_command`) - excessive agency in Python, outside the MCP fleet. |
| ATL-203 | high | The agent's tools combine shell execution with outbound network reach. |
| ATL-207 | high | Untrusted fetched content can reach the shell tool (toxic flow). |

The point: **the same fleet analysis that runs on MCP config runs on code.**
`fetch_page` is the entry (reads untrusted web content), `run_command` is the
pivot (shell), `post_result` is the exfiltration channel - three functions, one
internal attack path, found without a single line of config. A config-only
scanner sees an empty directory.

## Precision, not grep

A Python file is modeled as an agent only when it **imports a known agent
framework** (Anthropic, OpenAI Agents SDK, LangChain/LangGraph, CrewAI, AutoGen,
Pydantic AI, MCP/FastMCP, ...) **and defines at least one tool**. An ordinary
script that happens to call `subprocess` is never misread as an agent - the
low-false-positive gate the north star demands.
