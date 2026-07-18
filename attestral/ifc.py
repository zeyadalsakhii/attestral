"""Information-flow lattice over the system model (roadmap M6).

The lethal-trifecta (ATL-202) and taint-flow (ATL-207) findings are heuristic:
named capability groups co-occurring in one agent session. This layer attaches
confidentiality and integrity labels to each tool surface by capability, so the
same flow becomes a defensible *property* rather than a severity with an opinion:

- confidentiality: a HIGH source (reads private data) can reach a LOW egress sink
  (data leaves the trust boundary) with no declassifier on the path;
- integrity: a LOW source (attacker-influenceable input) can reach a HIGH sink
  (a trust-critical action) with no endorser on the path.

This is the classic Denning lattice specialized to an agent's tool fleet, and it
is what makes the finding citable (FIDES, CaMeL) instead of "these capabilities
co-occur". A declassifier / endorser is a modeled mitigation step (validation,
allowlist, human approval) that breaks the flow; no ingester emits one yet, so
today a violation stands whenever the labelled flow exists, and the finding says
so. When a declassifier signal lands, this layer clears the flow while the coarse
heuristics (ATL-202/207) still fire - the difference is the point.
"""
from __future__ import annotations

from dataclasses import dataclass

from attestral.model import SystemModel

# Capability -> lattice position.
# Confidentiality dimension: reads secret data (source) vs. lets data leave (sink).
_CONF_SOURCE = frozenset({"filesystem", "database", "saas_data", "memory"})
_EGRESS_SINK = frozenset({"network", "messaging"})
# Integrity dimension: ingests untrusted content (source) vs. acts on trust (sink).
_UNTRUSTED_SOURCE = frozenset({"network", "saas_data", "memory"})
_TRUSTED_SINK = frozenset({"shell"})
# Modeled mitigations that break a flow. None emitted yet; kept as the extension
# point so the lattice is future-correct rather than always-on.
_DECLASSIFIER_CAPS: frozenset = frozenset()


@dataclass(frozen=True)
class Violation:
    kind: str              # "confidentiality" | "integrity"
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    justification: str


def _labelled(model: SystemModel):
    """(component name, capability set) over every tool surface, composing the
    delegation hop the same way the capability rules do."""
    return [(c.name, set(c.attr("_capabilities") or [])) for c in model.tool_surfaces()]


def has_declassifier(model: SystemModel) -> bool:
    return any(caps & _DECLASSIFIER_CAPS for _, caps in _labelled(model))


def _ends(labelled, source_caps, sink_caps) -> tuple[tuple[str, ...], tuple[str, ...]]:
    src = tuple(sorted({n for n, caps in labelled if caps & source_caps}))
    snk = tuple(sorted({n for n, caps in labelled if caps & sink_caps}))
    return src, snk


def violations(model: SystemModel) -> list[Violation]:
    """Every information-flow lattice violation in the model. Empty if the flow
    is broken by a declassifier or an endpoint is absent."""
    labelled = _labelled(model)
    if has_declassifier(model):
        return []
    out: list[Violation] = []

    csrc, egress = _ends(labelled, _CONF_SOURCE, _EGRESS_SINK)
    if csrc and egress:
        out.append(Violation(
            "confidentiality", csrc, egress,
            f"High-confidentiality source(s) [{', '.join(csrc)}] can reach "
            f"low-confidentiality egress sink(s) [{', '.join(egress)}] with no "
            "declassifier on the path, so confidential data can leave the boundary.",
        ))

    isrc, tsink = _ends(labelled, _UNTRUSTED_SOURCE, _TRUSTED_SINK)
    if isrc and tsink:
        out.append(Violation(
            "integrity", isrc, tsink,
            f"Low-integrity source(s) [{', '.join(isrc)}] can reach high-integrity "
            f"sink(s) [{', '.join(tsink)}] with no endorser on the path, so untrusted "
            "input can drive a trust-critical action.",
        ))
    return out
