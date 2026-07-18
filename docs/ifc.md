# The information-flow lattice (M6)

Attestral's headline finding is the lethal trifecta: an agent whose tools can
read private data and reach an outbound channel, so one injected instruction
anywhere in its inputs can exfiltrate what it sees. Until now that finding was
*heuristic* - named capability groups (ATL-202) co-occurring in one session. A
reviewer who has read the information-flow literature sees "these capabilities
co-occur" and discounts it. This layer answers that reviewer.

## The labels

Every tool surface gets two labels, the classic Denning dimensions:

- **Confidentiality.** A surface that reads secret data is a *high* source
  (filesystem, database, SaaS data, memory). A surface that lets data leave the
  trust boundary is a *low* egress sink (network, messaging).
- **Integrity.** A surface that ingests attacker-influenceable content is a
  *low* source (network, SaaS data, memory). A surface that performs a
  trust-critical action is a *high* sink (shell/execution).

## The violations

Two lattice properties, each precise:

- **Confidentiality violation.** A high-confidentiality source can reach a
  low-confidentiality egress sink with no declassifier on the path. Confidential
  data can leave the boundary. This is the lethal trifecta, stated as a property.
- **Integrity violation.** A low-integrity source can reach a high-integrity
  sink with no endorser on the path. Untrusted input can drive a trust-critical
  action. This is indirect-injection-to-execution, stated as a property.

ATL-217 fires with the named label path, for example: *"High-confidentiality
source(s) [filesystem, jira] can reach low-confidentiality egress sink(s) [web]
with no declassifier on the path, so confidential data can leave the boundary."*
That is defensible and citable (FIDES, CaMeL), not a severity with an opinion.

## Declassifiers, and why the lattice is future-correct

A **declassifier** (confidentiality) or **endorser** (integrity) is a modeled
mitigation that breaks the flow: a validation step, an allowlist, a human
approval gate. When one sits between the labelled source and sink, the flow is
no longer a violation.

No ingester emits a declassifier signal today, so ATL-217 currently fires
whenever the labelled flow exists - the same fixtures ATL-202/207 flag. The
difference matters the moment a declassifier signal lands: ATL-217 will *clear*
the flow (the mitigation is real), while the coarse ATL-202/207 still fire on
the raw capability co-occurrence. The lattice is the precise instrument; the
heuristics are the smoke alarm. Detecting declassifiers in agent config is the
next step (roadmap), and it is why the lattice was built label-first rather than
bolted onto the existing rules.

## Where it sits

`attestral/ifc.py` (`violations(model)`) is pure structure over the
`SystemModel`, evaluated by the engine's `model_ifc_violation` matcher behind
ATL-217. It composes the delegation hop the same way the capability rules do, so
a code-defined agent's flows are covered too. Deterministic, offline, in the L1
deterministic layer alongside the attack-path and fleet reasoning.

Refs: Denning, "A Lattice Model of Secure Information Flow" (1976); FIDES; CaMeL.
