"""Cross-repo fleet modeling: the toxic flow that spans repositories.

Attestral's thesis is that agentic risk lives in the *integration* - a shell
tool here, an untrusted-input tool there, an egress channel somewhere else. When
those live in one repo, a single scan finds the flow. When they live in
different repos, no per-repo scanner, however good, can see it: each repo looks
fine on its own. This module builds ONE system model spanning several repos,
tags every component with the repo it came from, and finds the chain that only
completes across the repo boundary.

The headline finding (ATL-213) is deliberately narrow so it is never noise: it
fires only when the fleet's combined capabilities form a complete attack chain
(a way in, a way to run code, a way out) AND no single repo forms that chain
alone. That detection lives in the rule engine (keyed on the `_repo` tags this
module writes), so it is a real, documented rule; everything else - the
per-component rules, the reachability escalation, the attack-path synthesis -
runs over the merged model unchanged, so a medium finding in repo A can be
raised because repo B is what completes the chain.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from attestral.ingest import build_model
from attestral.model import Edge, SystemModel, TrustBoundary

# Capability roles, mirrored from paths.py (kept local, as redteam.py does, so
# the fleet reasoning does not reach into another module's private constants).
_ENTRY_TAINT_CAPS = {"network", "saas_data", "memory"}
_PIVOT_CAPS = {"shell"}
_EGRESS_CAPS = {"network", "messaging"}


def _repo_label(path: str | Path, taken: set[str]) -> str:
    """A short, unique label for a repo: its directory basename, disambiguated
    with a numeric suffix if two paths share one."""
    base = Path(path).resolve().name or "repo"
    label = base
    n = 1
    while label in taken:
        n += 1
        label = f"{base}#{n}"
    taken.add(label)
    return label


def build_fleet_model(paths: list[str | Path]) -> tuple[SystemModel, list[str]]:
    """Merge each repo's model into one, namespacing component ids and names by
    repo (`repoA/web`) so nothing collides and every attack-path rung reads with
    its origin. Returns the combined model and the ordered repo labels."""
    combined = SystemModel(
        boundaries=[
            TrustBoundary("cloud", "Cloud infrastructure"),
            TrustBoundary("cluster", "Kubernetes cluster"),
            TrustBoundary("agent_runtime", "Agent / MCP runtime"),
        ]
    )
    labels: list[str] = []
    taken: set[str] = set()
    for p in paths:
        label = _repo_label(p, taken)
        labels.append(label)
        m = build_model(p)
        idmap: dict[str, str] = {}
        for c in m.components:
            new_id = f"{label}::{c.id}"
            idmap[c.id] = new_id
            combined.add(replace(
                c,
                id=new_id,
                name=f"{label}/{c.name}",
                attributes={**c.attributes, "_repo": label},
            ))
        for e in m.edges:
            # Remap endpoints that are real components; leave shared sentinels
            # (taint:*, boundary:*) global so the fleet taint graph joins up.
            combined.edges.append(Edge(
                source_id=idmap.get(e.source_id, e.source_id),
                target_id=idmap.get(e.target_id, e.target_id),
                kind=e.kind,
                attributes=dict(e.attributes),
            ))
    return combined, labels


def _repo_caps(model: SystemModel) -> dict[str, set[str]]:
    """repo label -> the union of capabilities its tool surfaces grant."""
    out: dict[str, set[str]] = {}
    for c in model.tool_surfaces():
        repo = c.attr("_repo") or "unknown"
        out.setdefault(repo, set()).update(c.attr("_capabilities") or [])
    return out


def _roles(repo_caps: dict[str, set[str]]) -> tuple[set[str], set[str], set[str]]:
    """(repos that can be an entry, a pivot, an impact) across the fleet."""
    entry = {r for r, caps in repo_caps.items() if caps & _ENTRY_TAINT_CAPS}
    pivot = {r for r, caps in repo_caps.items() if caps & _PIVOT_CAPS}
    impact = {r for r, caps in repo_caps.items() if caps & _EGRESS_CAPS}
    return entry, pivot, impact


def render_fleet_overview(model: SystemModel, labels: list[str], *,
                          color: bool | None = None) -> str:
    """The cross-repo preamble: each repo and the capabilities it contributes to
    the fleet, so the reader sees which repo supplies which rung of any chain."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    repo_caps = _repo_caps(model)
    lines = [_bold(f"Fleet: {len(labels)} repos", color)]
    for label in labels:
        caps = ", ".join(sorted(repo_caps.get(label, set()))) or "no tool capabilities"
        n = len([c for c in model.components if c.attr("_repo") == label])
        lines.append(f"  {_bold(label, color)}  {_dim(f'{n} components', color)} · reach: {caps}")
    entry, pivot, impact = _roles(repo_caps)
    if entry and pivot and impact and not (entry & pivot & impact):
        lines.append("")
        lines.append(_paint(
            "cross-repo chain: entry [" + ", ".join(sorted(entry)) + "] -> pivot ["
            + ", ".join(sorted(pivot)) + "] -> impact [" + ", ".join(sorted(impact)) + "]",
            "1;31", color))
    return "\n".join(lines)
