# Fleet fixture: the reader repo

Half of a cross-repo toxic flow. On its own this repo is a data-reader agent: a
web-fetch tool (untrusted input) and a Slack tool (outbound). It has **no shell,
no code execution**, so scanned alone it shows no attack path.

```bash
attestral scan examples/fleet-repo-reader --quiet
# 2 components · 2 findings · 1 high · 1 medium   (no attack path)
```

Paired with [`fleet-repo-runner`](../fleet-repo-runner) (which has the shell),
`attestral fleet` completes the chain across the repo boundary. See that repo's
README for the combined run.
