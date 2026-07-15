"""Reachability-based severity: tie a finding's rating to a walked attack chain.

A severity band is defensible when the reviewer can see why it was assigned.
When a finding's component sits on an attack path the symbolic walk
(`redteam.build_proofs`) shows reachable in the modeled design - a way in, a
way to run code, a way out - the finding is annotated with that chain and its
severity is raised one band, never above the chain's own severity. A raised
HIGH ships with the entry -> pivot -> impact path that justifies it, so it is
trusted rather than argued with.

Honest scope, inherited from the walk it reuses: reachability is computed over
declared capability, a sound over-approximation, and is a necessary, not
sufficient, condition for exploitation. The inverse move is deliberately never
made - a finding off every chain is not downgraded, because the absence of a
modeled path is not evidence of safety.

Deterministic, zero-dependency, runs on every scan.
"""
from __future__ import annotations

from attestral.model import Finding, Severity, SystemModel
from attestral.redteam import Proof, build_proofs

# Severity bands indexed by rank, for the one-band escalation step.
_BANDS = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _chain_line(proof: Proof) -> str:
    """The walked chain as one compact line, components grouped by rung:
    `internal chain: web -> ops -> web`."""
    stages = []
    for role in ("entry", "pivot", "impact"):
        names = [s.component for s in proof.steps if s.role == role]
        if names:
            stages.append(", ".join(names))
    return f"{proof.kind} chain: " + " -> ".join(stages)


def _roles_by_component(proof: Proof) -> dict[str, list[str]]:
    """component name -> the rung(s) it fills, in walk order. One component can
    fill several rungs (a fetch tool is both the entry and the egress)."""
    out: dict[str, list[str]] = {}
    for s in proof.steps:
        roles = out.setdefault(s.component, [])
        if s.role not in roles:
            roles.append(s.role)
    return out


def annotate_reachability(model: SystemModel, findings: list[Finding]) -> list[str]:
    """Annotate every finding whose component is a rung on a reachable attack
    chain, and raise its severity one band, capped at the chain's own severity
    (an internal chain is HIGH, so it never pushes a finding to critical).

    Mutates the findings in place and returns human-readable notes for the
    caller to echo. Idempotent: an already-annotated finding is left alone, so
    a second pass never double-escalates. Model-level (fleet) findings are not
    touched - the chain is already their content.
    """
    proofs = build_proofs(model)
    if not proofs:
        return []

    # Most severe chain first, so a component on both the external and the
    # internal chain carries the external (critical) context.
    best: dict[str, tuple[Proof, list[str]]] = {}
    for p in sorted(proofs, key=lambda p: -p.severity.rank):
        for name, roles in _roles_by_component(p).items():
            best.setdefault(name, (p, roles))

    annotated = raised = 0
    for f in findings:
        if f.reachability:
            continue
        component = model.get(f.component_id)
        if component is None or component.name not in best:
            continue
        proof, roles = best[component.name]
        f.reachability = _chain_line(proof)
        f.reachability_role = "+".join(roles)
        annotated += 1
        new_rank = min(f.severity.rank + 1, proof.severity.rank)
        if new_rank > f.severity.rank:
            f.escalated_from = f.severity.value
            f.severity = _BANDS[new_rank]
            raised += 1

    if not annotated:
        return []
    note = f"reachability: {annotated} finding(s) sit on a walked attack chain"
    if raised:
        note += f"; {raised} raised one severity band"
    return [note]
