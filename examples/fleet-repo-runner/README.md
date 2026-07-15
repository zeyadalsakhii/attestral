# Fleet fixture: the runner repo, and the cross-repo flow (M12)

On its own this repo is an ops-runner agent: a single shell tool. It has a
critical shell finding, but **no untrusted input and no egress**, so scanned
alone there is no attack path - nothing can drive the shell, and nothing carries
data out.

```bash
attestral scan examples/fleet-repo-runner --quiet
# 1 component · 1 finding · 1 critical   (no attack path)
```

Neither this repo nor [`fleet-repo-reader`](../fleet-repo-reader) shows a toxic
flow alone. The flow only exists **across** them: the reader ingests untrusted
web content, this repo runs the shell, the reader carries the result out. That
is the flow a per-repo scanner structurally cannot see.

```bash
attestral fleet examples/fleet-repo-reader examples/fleet-repo-runner
```

```
Fleet: 2 repos
  fleet-repo-reader  2 components · reach: messaging, network
  fleet-repo-runner  1 components · reach: shell

cross-repo chain: entry [fleet-repo-reader] -> pivot [fleet-repo-runner] -> impact [fleet-repo-reader]
```

```
Attack paths (1)
  internal chain:
    entry: untrusted input ingested by a tool  [fleet-repo-reader/web]
    pivot: code execution  [fleet-repo-runner/ops]
    impact: exfiltration  [fleet-repo-reader/slack, fleet-repo-reader/web]
```

The fleet run fires **ATL-213 (cross-repo toxic flow)**, names which repo
contributes each rung, and - because the fleet now completes the chain -
reachability raises the reader's outbound-fetch finding from medium to high. A
single-repo scan of either repository fires none of this.

## Why the rule is narrow

ATL-213 fires **only** when the fleet's union of capabilities completes a chain
that **no single repo completes alone**. If one repo already had the whole
trifecta, its own scan would catch it and the cross-repo finding would add
nothing - so it stays silent, and the rule never becomes noise.
