"""Smoke test: the realistic dev-team fixture surfaces the fleet-level findings."""
from attestral.ingest import build_model
from attestral.rules import RuleEngine


def test_real_world_fleet_findings_fire():
    model = build_model("examples/real-world-agent")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    # The three findings only a system model can produce.
    assert {"ATL-202", "ATL-203", "ATL-207"} <= ids
