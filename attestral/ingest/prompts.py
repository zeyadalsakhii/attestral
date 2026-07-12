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

from pathlib import Path

from attestral.model import Component, SystemModel

# Cap so a runaway file can never dominate context / a classifier window.
_MAX_CHARS = 20_000

_NAME_HINTS = ("system-prompt", "system_prompt", "systemprompt")


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
        files = [p] if _qualifies(p) else []
    else:
        seen: set[Path] = set()
        files = []
        for pattern in ("*.txt", "*.md", "*.prompt"):
            for f in p.rglob(pattern):
                if f not in seen and _qualifies(f):
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
        model.add(
            Component(
                id=f"system_prompt.{f.stem}",
                type="system_prompt",
                name=f.stem,
                source=str(f),
                attributes={"content": content},
                trust_boundary="agent_runtime",
            )
        )
    return model
