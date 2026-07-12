"""MCP server configuration ingestion (claude_desktop_config.json / .mcp.json style)."""
from __future__ import annotations

import json
from pathlib import Path

from attestral.model import Component, SystemModel

_SECRET_HINTS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")


def _tool_descriptions(tools) -> list[dict]:
    """Normalize a manifest's `tools` into [{name, description}] entries."""
    out: list[dict] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("description"):
                out.append(
                    {"name": str(t.get("name", "")), "description": str(t["description"])}
                )
    elif isinstance(tools, dict):
        for tname, t in tools.items():
            desc = t.get("description") if isinstance(t, dict) else t
            if desc:
                out.append({"name": str(tname), "description": str(desc)})
    return out


def ingest_mcp(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        list(p.rglob("*.mcp.json")) + list(p.rglob("mcp*.json")) + list(p.rglob("claude_desktop_config.json"))
    )
    for f in files:
        try:
            data = json.loads(f.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        for name, cfg in servers.items():
            attrs: dict = {}
            if isinstance(cfg, dict):
                attrs["command"] = cfg.get("command", "")
                attrs["args"] = cfg.get("args", [])
                attrs["url"] = cfg.get("url", "")
                env = cfg.get("env", {}) or {}
                attrs["env_keys"] = list(env.keys())
                attrs["_env_has_secrets"] = any(
                    any(h in k.upper() for h in _SECRET_HINTS) for k in env
                )
                # Natural-language surfaces (server + tool descriptions) are
                # kept for the optional ML layer to score for injection text.
                if cfg.get("description"):
                    attrs["description"] = str(cfg["description"])
                tool_descs = _tool_descriptions(cfg.get("tools"))
                if tool_descs:
                    attrs["_tool_descriptions"] = tool_descs
            model.add(
                Component(
                    id=f"mcp_server.{name}",
                    type="mcp_server",
                    name=name,
                    source=str(f),
                    attributes=attrs,
                    trust_boundary="agent_runtime",
                )
            )
    return model
