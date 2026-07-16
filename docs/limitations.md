# What Attestral catches, and what it does not

A security tool you can trust is one that is honest about its edges. In a field
full of overclaiming, the tool that documents where it stops is the one a
skeptical engineer keeps. This is that page: the scope boundaries, the known
blind spots, and where our own detection breaks. None of it is hidden in a
footnote, because the limits are part of the product.

## The one-line scope

Attestral is a **design review**, not a SAST tool. It reads the *declared*
surface, the MCP config, the agent wiring, the system prompts, the Terraform and
Kubernetes, builds a system model, and reasons over it. It does not read the
inside of a tool's implementation. It tells you the capability a tool *grants*
and the flows that capability enables; it will not find a logic bug inside that
tool's code. That is a deliberate boundary, not a gap we are hiding: design-time
review is where the highest-leverage, cheapest-to-fix issues live, and it is a
different job from line-level static analysis.

## What it does not do (by design)

- **It does not execute anything against your live agent.** The adversarial
  validation (`attestral validate`) is a symbolic walk over the model's declared
  edges, plus an optional sandbox harness with a planted canary. It never runs a
  payload against a system you operate. Execution against a fingerprinted,
  own-target-only system stays gated and future.
- **Reachability is necessary, not sufficient, for exploitation.** A reachable
  attack path means the design *allows* the flow over declared capability, a
  sound over-approximation. It does not prove the LLM would follow an injection,
  that no guardrail or human-approval step sits in the path, or that the sink is
  reachable at runtime. We reframed away from the word "proof" for exactly this
  reason. Treat a reachable HIGH as "worth prioritizing," not "already exploited."
- **It reads declared config, not arbitrary application logic.** A secret loaded
  through three layers of indirection, a capability granted at runtime by code we
  do not model, an env var resolved by a wrapper script: these can be missed. The
  scan preamble says this on every run so a clean result never reads as "nothing
  here," only as "nothing in the surfaces Attestral reviews."

## Known blind spots (where we can miss)

- **HCL resolution depth.** The Terraform resolver does not yet evaluate
  cross-variable interpolation, so a misconfiguration behind a `var.` reference
  can sit unseen. This is why the TerraGoat benchmark number is reported as a
  *floor*, gated by resolver depth, not a measure of the cloud pack's reach.
- **Capability classification is coarse on purpose.** Capabilities are inferred
  from substring hints on launch commands and, for agent code, from the symbols a
  tool's body uses. A novel or deliberately obfuscated tool can be misclassified.
  The bias is toward *missing* a capability (one fewer cross-cutting finding)
  rather than a per-server false alarm, because a noisy scanner gets uninstalled.
- **The ML tier is probabilistic.** The prompt-injection classifier (heuristic,
  ONNX, or DeBERTa) can miss a cleverly framed injection and can flag benign
  instructional prose. It is a knob with a tunable threshold, not an oracle, and
  its findings are tagged `origin: ml` so they are never mixed with the
  deterministic core.
- **Agent-code ingestion needs a recognizable shape.** A file is modeled as an
  agent only when it imports a known framework and defines a tool. Agent logic in
  an unrecognized framework, or generated at runtime, will not be modeled.
- **The fleet is what you point it at.** `attestral fleet` models the repos you
  give it. It cannot yet discover an organization's entire agent estate on its
  own, so a cross-repo toxic flow involving a repo you did not include is invisible.

## Where our own detection breaks (adversarial honesty)

Static-benchmark wins evaporate under adaptive attack, so we measure ourselves
against that, not just against fixtures we wrote:

- The `evaluation/` harness tracks a benign-corpus **false-positive rate** in CI,
  budgeted to zero on clean designs, so a rule that starts over-firing fails the
  suite. The real-world sweep of 33 public MCP servers reports the actual
  false-positive read, including the borderline classes we deliberately do *not*
  headline (the Windows `cmd /c npx` idiom read as a shell, benign instructional
  text scored by the heuristic tier).
- A defense-aware attacker who knows our capability hints can name a tool to dodge
  them, or split a trifecta across a session boundary we do not model. We treat
  closing these as roadmap work (defense-aware evaluation), and we would rather
  say so than imply coverage we do not have.

## Reporting and posture

Security issues go to the process in [`SECURITY.md`](../SECURITY.md). The design
commitments there, fail-closed matchers, no `eval` in the rule path, a
deterministic offline-verifiable evidence chain, are testable properties, not
promises. If you find a case where Attestral claims more than it delivers, that
is itself a bug worth reporting.
