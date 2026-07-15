from attestral.ingest import build_model
from attestral.rules import RuleEngine


def _findings():
    model = build_model("examples/demo-project")
    return model, RuleEngine().evaluate(model)


def test_model_builds_components():
    model, _ = _findings()
    assert len(model.components) == 8  # 4 tf + 4 mcp


def test_cloud_rules_fire():
    _, findings = _findings()
    ids = {f.rule_id for f in findings}
    assert {"ATL-001", "ATL-002", "ATL-003", "ATL-004"} <= ids


def test_mcp_rules_fire():
    _, findings = _findings()
    ids = {f.rule_id for f in findings}
    assert {"ATL-101", "ATL-102", "ATL-103", "ATL-104"} <= ids


def test_cross_boundary_model_rule_fires():
    _, findings = _findings()
    assert "ATL-201" in {f.rule_id for f in findings}


def test_auto_install_rule_fires_on_dash_y():
    # ATL-105: `npx -y` style auto-install at launch. vulnerable-agent plants
    # it on two servers; assert the components so the check is direct, not
    # just implied by the fixture-README count sync.
    model = build_model("examples/vulnerable-agent")
    findings = RuleEngine().evaluate(model)
    hits = {f.component_id for f in findings if f.rule_id == "ATL-105"}
    assert hits == {"mcp_server.filesystem", "mcp_server.web"}


def test_findings_sorted_by_severity():
    _, findings = _findings()
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)
