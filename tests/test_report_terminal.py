"""Terminal report rendering: fleet inventory and summary grammar."""
import json

from attestral.ingest.local_config import build_local_model
from attestral.model import SystemModel
from attestral.report_terminal import render_fleet, render_scan


def _local_model(tmp_path, servers):
    cfg = tmp_path / "home" / ".claude.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"mcpServers": servers}))
    model, _ = build_local_model(home=tmp_path / "home", cwd=tmp_path / "cwd",
                                 platform="darwin")
    return model


def test_render_fleet_lists_every_server_with_reach_and_source(tmp_path):
    model = _local_model(tmp_path, {
        "notes": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"]},
        "metrics": {"url": "https://metrics.example/mcp", "env": {"METRICS_TOKEN": "x"}},
    })
    text = render_fleet(model, color=False)
    assert "Agent tool surface (2 servers)" in text
    assert "notes" in text and "stdio" in text
    assert "metrics" in text and "remote" in text
    assert "reach: filesystem" in text          # capability classes are shown
    assert ".claude.json" in text               # so is where each server came from


def test_render_fleet_empty_model_renders_nothing():
    assert render_fleet(SystemModel(), color=False) == ""


def test_summary_grammar_singular(tmp_path):
    model = _local_model(tmp_path, {
        "notes": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"]},
    })
    text = render_scan(model, [], "local", color=False)
    assert "1 component · 0 findings" in text
