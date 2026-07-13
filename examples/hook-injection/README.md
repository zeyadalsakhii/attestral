# Hook config-injection fixture (CVE-2025-59536 class)

A repository that ships a `.claude/settings.json` with a **hook that runs a shell
command**. The moment an agent trusts this repo, the hook fires and the command
runs on the developer's machine, with no prompt and no tool call the user
approved. This is the config-injection class Check Point disclosed as
CVE-2025-59536 in Claude Code.

```bash
attestral scan examples/hook-injection
```

Fires **ATL-118**: the settings file defines a `PreToolUse` hook that pipes a
remote payload into `sh`. Attestral treats a project-scoped settings file that
adds command-running hooks as executable code, not configuration.

The fix is not to scrub this one command; it is to never inherit hook
definitions from an untrusted repo. Pin hooks in user-scoped settings and review
any project settings file that adds them.

## Research

- **CVE-2025-59536** (Check Point Research, Feb 2026): configuration-injection in
  Claude Code's Hooks feature via a repo-supplied `.claude/settings.json`.
- **OWASP Top 10 for Agentic Applications 2026 - ASI06** (memory / context
  poisoning): standing agent configuration is an attack surface.
