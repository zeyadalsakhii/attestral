"""System-prompt / agent-instruction ingestion.

Agentic systems are steered by natural-language instructions - system
prompts, tool descriptions, agent playbooks. Those are a first-class attack
surface (prompt injection, jailbreaks, tool-poisoning text) that the
deterministic rules cannot see, because the risk is in the *words*, not in a
config flag. This ingester pulls that text into the model as `system_prompt`
components carrying a `content` attribute; the optional ML layer
(`attestral[ml]`) is what scores that content.

Patterns are deliberately tight so a scan does not sweep every Markdown file
in a repo into the model. A file qualifies if it is under a `prompts/`
directory, has a `.prompt[.txt|.md]` extension, or its name marks it as a
system prompt / agent instruction set.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from attestral.model import Component, SystemModel

# Cap so a runaway file can never dominate context / a classifier window.
_MAX_CHARS = 20_000

_NAME_HINTS = ("system-prompt", "system_prompt", "systemprompt")

# Standing agent-instruction files: memory/context that steers the agent on
# every run (OWASP ASI06). Poisoning one of these is persistent, not
# per-session. Matched by exact filename (case-insensitive).
_INSTRUCTION_FILES = {
    "claude.md", "agents.md", "agent.md", ".cursorrules", ".windsurfrules",
    ".github/copilot-instructions.md", "copilot-instructions.md",
    ".clinerules", ".aider.conf.yml", "gemini.md", "codex.md",
}


def _is_instruction_file(f: Path) -> bool:
    name = f.name.lower()
    if name in _INSTRUCTION_FILES:
        return True
    # copilot-instructions.md lives under .github/; match on the tail.
    return name == "copilot-instructions.md"


def _is_skill_file(f: Path) -> bool:
    """A packaged agent skill (Claude/Cursor): a SKILL.md manifest, usually at
    <root>/skills/<name>/SKILL.md. Standing, auto-loaded instructions that can
    also declare tool grants - so it is both a poisoning surface and an
    excessive-agency surface."""
    return f.name.lower() == "skill.md"


def _skill_tool_grant(content: str) -> bool | None:
    """Parse a SKILL.md YAML frontmatter for an `allowed-tools` grant that hands
    the skill shell/exec or wildcard tool access. Returns True/False when the
    grant is declared, or None when it is not (we never guess). Fails closed:
    unparseable frontmatter yields None, not a finding."""
    if not content.startswith("---"):
        return None
    end = content.find("\n---", 3)
    if end == -1:
        return None
    import yaml
    try:
        meta = yaml.safe_load(content[3:end])
    except yaml.YAMLError:
        return None
    if not isinstance(meta, dict):
        return None
    grant = meta.get("allowed-tools", meta.get("allowed_tools"))
    if grant is None:
        return None
    tokens = grant if isinstance(grant, list) else str(grant).replace(",", " ").split()
    return any(
        t == "*" or "bash" in t or "shell" in t or t.startswith("exec")
        for t in (str(x).lower() for x in tokens)
    )


def _world_writable(f: Path) -> bool:
    """True if any user on the host can rewrite the file (or its dir) - a
    standing-instruction file anyone can edit is a persistent poisoning vector.
    Fail-closed: an unstattable file is not reported as writable."""
    try:
        if os.stat(f).st_mode & stat.S_IWOTH:
            return True
        return bool(os.stat(f.parent).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _qualifies(f: Path) -> bool:
    name = f.name.lower()
    if name.endswith((".prompt", ".prompt.txt", ".prompt.md")):
        return True
    if any(h in name for h in _NAME_HINTS):
        return True
    return "prompts" in {part.lower() for part in f.parent.parts}


def ingest_prompts(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        files = [p] if (_qualifies(p) or _is_instruction_file(p) or _is_skill_file(p)) else []
    else:
        seen: set[Path] = set()
        files = []
        for pattern in ("*.txt", "*.md", "*.prompt", "*.cursorrules", "*.windsurfrules"):
            for f in p.rglob(pattern):
                if f not in seen and (_qualifies(f) or _is_instruction_file(f) or _is_skill_file(f)):
                    seen.add(f)
                    files.append(f)
        # Dotfile instruction sets (.cursorrules, .windsurfrules, .clinerules)
        # are not caught by the extension globs above.
        for f in p.rglob(".*rules"):
            if f.is_file() and f not in seen and _is_instruction_file(f):
                seen.add(f)
                files.append(f)
        files.sort()
    for f in files:
        try:
            content = f.read_text(errors="ignore")[:_MAX_CHARS]
        except OSError:
            continue
        if not content.strip():
            continue
        skill = _is_skill_file(f)
        instruction = skill or _is_instruction_file(f)
        ctype = "agent_instruction" if instruction else "system_prompt"
        attrs: dict = {"content": content}
        if instruction:
            # Deterministic ASI06 signal: a standing-instruction file the whole
            # host can rewrite is a persistent poisoning vector (ATL-113). The
            # poisoning *text* itself is the ML layer's job, via `content`.
            attrs["_world_writable"] = _world_writable(f)
        if skill:
            attrs["_is_skill"] = True
            grant = _skill_tool_grant(content)
            if grant is not None:
                attrs["_skill_broad_tools"] = grant  # ATL-116
        # Skills are all named SKILL.md, so key the component on their folder.
        comp_name = f.parent.name if skill else (f.stem or f.name)
        model.add(
            Component(
                id=f"{ctype}.{comp_name}",
                type=ctype,
                name=comp_name,
                source=str(f),
                attributes=attrs,
                trust_boundary="agent_runtime",
            )
        )
    return model
