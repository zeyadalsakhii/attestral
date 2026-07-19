# Attested-agent fixture: the conformance-attestation flagship

One reproducible scenario that proves the whole moat in sequence: a design a scan
flags on a cross-boundary (lethal-trifecta) path, compiled to both policy
targets, a runtime stream that drifts (DRF-008), and a signed conformance
attestation a third party can verify offline - plus a tamper case that fails.

## The design

`.mcp.json` wires two MCP servers into one agent runtime:

- **internal-tools** - a filesystem server scoped to `/srv/agent-data`, holding a
  secret (`DATA_API_TOKEN`) in its env. Private-data access.
- **web-fetch** - `mcp-server-fetch`, an outbound network channel that ingests
  untrusted external content.

Together they are the **lethal trifecta**: the agent can read private data and
reach an outbound channel, so one indirect prompt injection anywhere in its
inputs can quietly exfiltrate what it reads. No single server is the finding;
the risk is the fleet.

## What fires

```bash
attestral scan examples/attested-agent/
```

2 components · 5 findings · 1 critical · 2 high · 2 medium

| Rule | Severity | Why |
|---|---|---|
| **ATL-202** | critical | **Tool fleet forms an exfiltration chain (lethal trifecta).** The assembled cross-boundary path. |
| ATL-105 | high | `internal-tools` auto-installs a package at launch (`npx -y`). |
| ATL-217 | high | Information-flow lattice violation across the fleet. |
| ATL-104 | medium | Secret passed to `internal-tools` via env. |
| ATL-107 | medium | `web-fetch` grants outbound network access. |

## The runtime drift

`events.jsonl` is a five-event stream. Four events are benign and conforming
(`internal-tools` reading files under its attested root, `web-fetch` fetching).
The fourth event has `internal-tools` exercise a **`shell`** capability its
attested envelope (`[filesystem]`) never authorized - the opaque-wrapper case, a
filesystem server that shells out. That trips **DRF-008** (unauthorized runtime
capability), the single, legible drift in the stream.

## The copyable sequence

```bash
# 1. Scan flags the cross-boundary path
attestral scan examples/attested-agent/

# 2. Compile both policy targets from the attested design
attestral compile examples/attested-agent/ --target cedar -o attested-policy.cedar
attestral compile examples/attested-agent/ -o mcp-guard-policy.yaml

# 3. Drift: DRF-008 fires on the out-of-envelope shell capability
attestral drift mcp-guard-policy.yaml examples/attested-agent/events.jsonl
#   5 events · 1 drift findings  (DRF-008)

# 4. Attest: bind design + both policies + the drift verdict into one signed bundle
attestral attest examples/attested-agent/ \
    --runtime examples/attested-agent/events.jsonl \
    --gen-key demo --signer "demo@attestral.dev" -o attestation.json

# 5. Verify offline: recomputes every digest, re-runs drift, checks the signature
attestral attest --verify examples/attested-agent/ \
    --runtime examples/attested-agent/events.jsonl \
    --public-key demo.pub -o attestation.json
#   attestation CONFORMING · runtime verdict: DRIFT (DRF-008)
```

The bundle records `verdict: DRIFT [DRF-008]` and verification of that recorded
verdict still passes, because it is exactly what the events show. An attested
design whose runtime drifted is the honest, interesting case: the drift is
recorded in the signed verdict, not hidden.

## The tamper case

```bash
# Drop the DRF-008 event line and re-verify against the unchanged bundle
grep -v run_indexer examples/attested-agent/events.jsonl > tampered.jsonl
attestral attest --verify examples/attested-agent/ \
    --runtime tampered.jsonl --public-key demo.pub -o attestation.json
#   attestation FAILED - first failing step: runtime.events
```

The events digest changes and re-running drift flips the verdict, so verification
fails and names the step. Editing the design instead fails at `subject` and
`reviewChainHead`; hand-editing a policy fails at `policies.*`.

## Honest framing

This is a **tamper-evident, signature-based conformance attestation, not a formal
or mathematical proof of security**. It proves the runtime observed matches the
design reviewed and the policies compiled from it. It does not prove the design is
safe: a clean attestation over this trifecta design is still a trifecta design.
Conformance is correspondence, not soundness.
