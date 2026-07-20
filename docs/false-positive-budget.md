# The false-positive budget (M3)

A security scanner lives or dies on two numbers. Recall answers "does it catch
the real problems"; the false-positive rate answers "and can I leave it on
without drowning in noise." Attestral publishes and gates its recall (see
`evaluation/`). This layer is the other half: a per-finding confidence, a filter
that acts on it, and a benign-corpus false-positive rate that is a gated
contract, not a promise.

The pitch is simple. A noisy scanner gets muted, then uninstalled. The moment a
developer waives a finding they know is wrong, they stop trusting every finding.
So the tool has to be honest about which findings are load-bearing and which are
advisory, and it has to give the developer a single lever to keep only the ones
that are safe to fail a build on.

## Confidence

Every `Finding` carries a `confidence`: `high`, `medium`, or `low`. It is
distinct from the LLM judge's `judge_confidence` (a per-finding cross-examination
score) - this is a static property of how false-positive-prone the detection is.

- **Deterministic rules are `high` by contract.** They match a structural fact
  the ingester extracted: a public S3 bucket, a shell tool with no approval gate,
  an unauthenticated remote MCP server. There is no guessing, so there is no
  false positive on a benign design. This is the CI-safe set.
- **A rule can opt down.** A rule whose signal is genuinely advisory sets
  `confidence: low` in its YAML. Today that is ATL-201 ("agent runtime and cloud
  share no declared boundary controls"), an `info`-severity nudge to document a
  trust path, not a defect. It should never fail a build, and now it cannot slip
  into the gated set by accident.
- **The ML tier's confidence tracks its probability.** Prompt-injection scoring
  is probabilistic, so a hit at 0.95 is `high`, a hit at 0.75 is `medium`, and a
  borderline 0.6 is `low`. The bands live in `attestral.ml._confidence`. This is
  what lets a reviewer keep the confident injection findings and filter the
  maybes without turning the whole ML layer off.

## The lever: `--min-confidence`

```bash
attestral scan <path> --min-confidence high
```

drops every finding below the floor before the report, the waiver pass, and the
`--fail-on` gate, so a filtered finding neither prints nor trips CI. The command
reports how many it dropped:

```
--min-confidence high: 3 lower-confidence finding(s) filtered
```

The floor is applied after reachability annotation (which can raise a finding's
severity) but before waivers, so filtering and waiving compose without
surprising interactions. `--min-confidence high` is the recommended setting for a
blocking CI gate: it keeps the structural findings that cannot be wrong and sets
aside the probabilistic and advisory ones for a human to read.

In the terminal report, a finding below `high` is tagged inline
(`(confidence: low)`); high-confidence findings are untagged so the common case
stays uncluttered. In SARIF, confidence is a result property for downstream
consumers.

## Inline suppression

`--min-confidence` handles whole classes of low-signal findings. For the
individual false positive - the one finding a developer has looked at and
decided is fine - the lever is a one-line marker in the config it came from:

```jsonc
"web": { "command": "uvx", "args": ["mcp-server-fetch"] }  // attestral:ignore ATL-107 reason: egress is internal-only
```

The finding is waived in place, no separate file. It is matched by (rule id,
source file): a marker in the file a finding came from, naming its rule,
suppresses it. This is deliberately file-scoped - Attestral's findings key off
components and files, not source lines.

Crucially, an inline-suppressed finding is *waived, not deleted*. It stays in
the evidence chain tagged with the marker's file and reason, exactly like a
waiver-file entry, so silence always has a recorded cause and an auditor still
sees what was set aside. This is the same invariant the waiver file honors; the
only difference is ergonomics. Reach for the waiver file (`attestral accept`)
when the exception needs an expiry, an owner, or a content pin; reach for the
inline marker for the quick, local "yes, I know, this one is fine."

Because markers have to survive the parse, the MCP ingester reads JSONC: `//`
and `/* */` comments in a `.mcp.json` no longer break ingestion (and real
Claude Desktop / Cursor / VS Code configs, which are commented in practice, now
scan correctly). In comment-native formats (Terraform HCL, Kubernetes YAML) the
marker just rides an ordinary `#` comment.

## The contract

The benign false-positive rate is not documentation, it is a test. The
evaluation harness ships a benign corpus - hardened designs that a correct
scanner must stay quiet on (`evaluation/corpus/benign-*`). `tests/test_fp_budget.py`
scans that corpus and asserts that the `--min-confidence high` set is **empty**.
If a future rule ever fires high-confidence on a benign design, the suite goes
red before it can ship. The zero-FP claim for the CI-safe set is therefore
enforced, the same way recall is.

This is the honest framing of the whole layer: high-confidence findings are the
ones we are willing to be graded on, so we are graded on them.
