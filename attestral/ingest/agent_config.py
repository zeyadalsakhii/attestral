"""Agent settings / hook configuration ingestion.

A project-scoped agent settings file (`.claude/settings.json` and friends) can
define HOOKS that execute shell commands around tool use. A malicious repository
that ships such a file gets code execution on the developer's machine the moment
the agent trusts the repo - the config-injection class behind CVE-2025-59536 in
Claude Code. This ingester surfaces those files as `agent_config` components so
ATL-118 can flag command-running hooks.
"""
from __future__ import annotations

import json
from pathlib import Path

from attestral.model import Component, SystemModel

_SETTINGS_NAMES = ("settings.json", "settings.local.json")


def _hook_commands(hooks) -> list[str]:
    """Every shell command declared in a Claude-Code-style hooks block, which
    nests as {event: [{matcher, hooks: [{type: command, command: "..."}]}]}.
    Tolerant of shape drift: a `command` on either nesting level counts."""
    out: list[str] = []
    if not isinstance(hooks, dict):
        return out
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("command"):
                out.append(str(entry["command"]))
            inner = entry.get("hooks")
            if isinstance(inner, list):
                for h in inner:
                    if isinstance(h, dict) and h.get("command"):
                        out.append(str(h["command"]))
    return out


def _is_settings_file(f: Path) -> bool:
    return f.name in _SETTINGS_NAMES and ".claude" in {p.lower() for p in f.parts}


def ingest_agent_config(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        files = [p] if _is_settings_file(p) else []
    else:
        files = sorted(
            {f for name in _SETTINGS_NAMES for f in p.rglob(f".claude/{name}")}
        )
    for f in files:
        try:
            data = json.loads(f.read_text(errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        cmds = _hook_commands(data.get("hooks"))
        # Name the component after the directory holding .claude, so two repos'
        # settings files never collide on one id.
        anchor = f.parent.parent.name or f.parent.name
        model.add(
            Component(
                id=f"agent_config.{anchor}.{f.stem}",
                type="agent_config",
                name=f.name,
                source=str(f),
                attributes={"_hook_runs_commands": bool(cmds), "_hook_commands": cmds},
                trust_boundary="agent_runtime",
            )
        )
    return model
