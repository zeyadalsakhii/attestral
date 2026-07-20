# Endorsed information flow (ATL-217 integrity half clears)

The injection-to-execution fleet ATL-207/203 flag - an untrusted-input tool
(`fetch`) and a command runner in one session - with the fix those rules
recommend already applied: the runner is gated behind human approval
(`--require-approval`), so it is an endorser.

```bash
attestral scan examples/ifc-endorsed
```

- **ATL-207 (unsafe data flow) and ATL-203 (shell + network) still fire.** The
  heuristics see an untrusted-input tool and a command runner co-located and flag
  the composition, because raw capability co-occurrence is all they reason over.
- **ATL-217 (information-flow lattice) does NOT fire.** The lattice sees that the
  only trust-critical sink is approval-endorsed - a human must confirm before a
  command runs, so injected content cannot drive the action uninterrupted - and
  there is no open confidentiality flow. With no open violation, the precise
  finding clears.

This is the integrity twin of `examples/ifc-declassified` (egress allowlist
clears the confidentiality half). Compare `examples/vulnerable-agent`, whose
runner has no approval gate: there ATL-217 fires. Apply the recommended
human-approval endorser and the precise finding clears while the heuristic smoke
alarm still sounds.

The endorser is detected conservatively (`mcp.py::_requires_approval`, an
explicit approval token on a shell sink only). Note the model treats approval as
breaking the flow at the sink; proving the endorser sits on the specific source
-to-sink path, and detecting input-validation endorsers, are later refinements.
