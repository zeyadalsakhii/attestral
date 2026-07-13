# Real-world agent fixture

This is not a horror show. It is a **plausible dev-team coding agent**: a
filesystem server scoped to the repo, GitHub, Postgres, Slack, a web fetch tool,
and a command runner. Every server here is something a real team wires up on a
normal Tuesday.

```bash
attestral scan examples/real-world-agent
```

The point: each server looks fine on its own. The danger only shows up when you
look at the **fleet as one system**, which is exactly what Attestral does.

## The headline findings (only a system model sees these)

| Finding | Why it fires |
|---|---|
| **ATL-202 - lethal trifecta** | `filesystem` + `postgres` + `github` read private data; `slack` + `fetch` reach outside. One injected instruction in any content the agent reads can quietly exfiltrate what it can see. |
| **ATL-203 - shell + network** | `commands` runs shell and `fetch` reaches the internet: download-and-run / C2 from a single injection. |
| **ATL-207 - toxic flow** | Untrusted input (`fetch`, `github` issues/PRs) can reach the command runner: indirect-injection-to-code-execution. The source and sink servers are named in the finding. |

No per-server linter produces these, because no single server is the bug. The
combination is.

## The per-server findings

`commands` is shell-capable (ATL-103); `fetch` is an outbound channel (ATL-107);
`github` and `slack` hold credentials in env (ATL-104); every server auto-installs
with `npx -y` / `uvx` (ATL-105, supply chain). Each is a fair finding on its own,
but the fleet-level three above are the ones that would ruin your week.

## How to actually fix it

You do not need to delete Slack. Split the workflow so no single agent session
combines private-data access with unrestricted egress and shell, or gate the
egress and command tools behind human approval. Then re-scan: the trifecta
findings clear because the *path* is broken, even though every tool still exists.
