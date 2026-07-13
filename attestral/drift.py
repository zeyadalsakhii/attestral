"""Design-runtime drift detection.

Reads a JSONL stream of tool-call events (mcp-guard telemetry format:
one object per line with at least `server`, `tool`, and optionally
`args`, `url`, `ts`) and diffs each event against the compiled policy
derived from the attested design.

Fail-closed philosophy carries through: an event that references a server
absent from the attested model is CRITICAL drift - the deployed system has
grown beyond what was reviewed.
"""
from __future__ import annotations

import json
from pathlib import Path

from attestral.manifest import manifest_hash, normalize_tools
from attestral.model import Finding, Severity

DRIFT_RULES = {
    "DRF-001": ("Unattested server observed at runtime", Severity.CRITICAL),
    "DRF-002": ("Denied server invoked at runtime", Severity.CRITICAL),
    "DRF-003": ("Filesystem access outside attested roots", Severity.HIGH),
    "DRF-004": ("Non-TLS transport observed for TLS-constrained server", Severity.HIGH),
    "DRF-005": ("Tool manifest changed since attestation (rug-pull)", Severity.CRITICAL),
    "DRF-006": ("Runaway tool-call loop (resource drain)", Severity.HIGH),
    "DRF-007": ("Server call volume exceeds attested budget", Severity.MEDIUM),
}


def _mk(rule: str, server: str, detail: str, event_no: int) -> Finding:
    title, sev = DRIFT_RULES[rule]
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        component_id=f"mcp_server.{server}",
        description=(f"Event #{event_no}: {detail}" if event_no else detail),
        recommendation=(
            "Either revert the runtime change, or update the design, re-run the "
            "review, and re-compile the policy so deployment and review match."
        ),
        source="runtime-telemetry",
        origin="deterministic",
    )


def _path_in_roots(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def detect_drift(policy: dict, events: list[dict]) -> list[Finding]:
    servers: dict[str, dict] = policy.get("servers", {})
    findings: list[Finding] = []
    for i, ev in enumerate(events, 1):
        name = str(ev.get("server", ""))
        entry = servers.get(name)

        if entry is None:
            findings.append(_mk("DRF-001", name, f"server '{name}' is not in the attested design", i))
            continue
        if not entry.get("allow", False):
            findings.append(_mk("DRF-002", name, entry.get("reason", "denied by policy"), i))
            continue

        constraints = entry.get("constraints", {})
        roots = constraints.get("root_paths")
        if roots:
            for arg in [str(a) for a in ev.get("args", []) if str(a).startswith(("/", "~"))]:
                if not _path_in_roots(arg, roots):
                    findings.append(_mk("DRF-003", name, f"path '{arg}' outside attested roots {roots}", i))
        if constraints.get("transport") == "tls_only" and str(ev.get("url", "")).startswith("http://"):
            findings.append(_mk("DRF-004", name, f"plaintext url '{ev.get('url')}'", i))

        # Rug-pull check: an event may carry the server's current manifest
        # (or its precomputed hash). Re-hash with the same canonicalization
        # used at scan time and compare to the attested pin.
        attested = entry.get("manifest_sha256")
        if attested:
            observed = ""
            if ev.get("manifest_sha256"):
                observed = str(ev["manifest_sha256"])
            elif isinstance(ev.get("manifest"), dict):
                m = ev["manifest"]
                observed = manifest_hash(
                    m.get("command", ""), m.get("args"), m.get("url", ""),
                    normalize_tools(m.get("tools")),
                )
            if observed and observed != attested:
                findings.append(_mk(
                    "DRF-005", name,
                    f"observed manifest {observed[:16]}… != attested {attested[:16]}… "
                    "- the tool surface changed after review",
                    i,
                ))

    findings.extend(_budget_drift(policy, events))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings


def _call_signature(ev: dict) -> str:
    """Stable key for one tool call (server + tool + args), so repeats of the
    identical call - a runaway loop - collapse to the same signature."""
    args = json.dumps(ev.get("args", []), sort_keys=True, default=str)
    return f"{ev.get('server', '')}\x00{ev.get('tool', '')}\x00{args}"


def _budget_drift(policy: dict, events: list[dict]) -> list[Finding]:
    """Resource-drain / DoS checks (R7): runaway loops (DRF-006) and per-server
    call-volume overruns (DRF-007), enforced against the policy's budgets block.
    Aggregate over the whole event stream, so they run once, not per event."""
    budgets = policy.get("budgets") or {}
    loop_threshold = budgets.get("loop_repeat_threshold")
    max_calls = budgets.get("max_calls_per_server")
    out: list[Finding] = []

    if loop_threshold:
        repeats: dict[str, int] = {}
        first_seen: dict[str, tuple[int, dict]] = {}
        for i, ev in enumerate(events, 1):
            sig = _call_signature(ev)
            repeats[sig] = repeats.get(sig, 0) + 1
            first_seen.setdefault(sig, (i, ev))
        for sig, count in repeats.items():
            if count >= loop_threshold:
                i, ev = first_seen[sig]
                out.append(_mk(
                    "DRF-006", str(ev.get("server", "")),
                    f"tool '{ev.get('tool', '')}' called {count} times with identical "
                    f"arguments (loop threshold {loop_threshold}) - possible runaway loop",
                    i,
                ))

    if max_calls:
        per_server: dict[str, int] = {}
        for ev in events:
            per_server[str(ev.get("server", ""))] = per_server.get(str(ev.get("server", "")), 0) + 1
        for server, count in sorted(per_server.items()):
            if count > max_calls:
                out.append(_mk(
                    "DRF-007", server,
                    f"{count} calls exceed the attested budget of {max_calls} for this server",
                    0,
                ))
    return out


def load_events(path: str | Path) -> list[dict]:
    events = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
