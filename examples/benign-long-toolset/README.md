# Benign long tool set: the false-positive control for cross-tool reassembly

A legitimately large multi-tool MCP server: a repository helper with thirteen
ordinary tool descriptions ("Creates an issue in the repository ...", "Lists the
open pull requests ...", and so on). None is injection-shaped, and the union of
all thirteen is long but scores nowhere near the prompt-injection threshold.

This is the paired control for [`split-tool-poisoning`](../split-tool-poisoning).
It proves the fleet-level cross-tool reassembly pass (ATL-ML-002) fires on a real
split payload, not on any server that simply has many tools. The union-vs-max gap
guard is what separates the two: a benign tool set has every fragment near zero
and a union near zero, so there is no emergent signal to flag.

```bash
attestral scan examples/benign-long-toolset
# 1 component · 0 findings   (clean: no ATL-ML-002 despite thirteen tools)
```
