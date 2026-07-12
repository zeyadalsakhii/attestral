"""Directory scanner: routes files to the right ingesters and returns one model."""
from __future__ import annotations

from pathlib import Path

from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.ingest.mcp import ingest_mcp
from attestral.ingest.prompts import ingest_prompts
from attestral.ingest.terraform import ingest_terraform
from attestral.model import SystemModel, TrustBoundary


def build_model(path: str | Path) -> SystemModel:
    model = SystemModel(
        boundaries=[
            TrustBoundary("cloud", "Cloud infrastructure"),
            TrustBoundary("cluster", "Kubernetes cluster"),
            TrustBoundary("agent_runtime", "Agent / MCP runtime"),
        ]
    )
    ingest_terraform(path, model)
    ingest_kubernetes(path, model)
    ingest_mcp(path, model)
    ingest_prompts(path, model)
    return model
