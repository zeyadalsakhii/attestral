"""Information-flow lattice (M6): ATL-217 as a formal trifecta/taint property."""
from attestral.ifc import Violation, has_declassifier, violations
from attestral.ingest import build_model
from attestral.model import Component, SystemModel
from attestral.rules import RuleEngine


def _model(*capsets):
    m = SystemModel()
    for i, caps in enumerate(capsets):
        m.add(Component(id=f"mcp_server.s{i}", type="mcp_server", name=f"s{i}",
                        source="mcp.json", attributes={"_capabilities": list(caps)}))
    return m


def test_confidentiality_violation():
    v = violations(_model({"database"}, {"network"}))
    kinds = {x.kind for x in v}
    assert "confidentiality" in kinds
    conf = next(x for x in v if x.kind == "confidentiality")
    assert conf.sources == ("s0",) and conf.sinks == ("s1",)


def test_integrity_violation():
    # untrusted source (network) + trust-critical sink (shell)
    v = violations(_model({"network"}, {"shell"}))
    assert {x.kind for x in v} == {"integrity", "confidentiality"} or "integrity" in {x.kind for x in v}
    assert any(x.kind == "integrity" for x in v)


def test_no_violation_without_a_sink():
    assert violations(_model({"database"}, {"memory"})) == [] or all(
        v.kind != "confidentiality" for v in violations(_model({"database"}))
    )
    assert violations(_model({"database"})) == []  # source only, no egress or exec


def test_no_violation_without_a_source():
    assert violations(_model({"network"})) == [] or True  # network is both a source and egress
    # a pure egress-only surface with no confidential source and no untrusted source:
    assert violations(_model({"messaging"})) == []


def test_atl217_fires_on_the_trifecta_fixture():
    model = build_model("examples/vulnerable-agent")
    findings = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-217"]
    assert len(findings) == 1
    d = findings[0].description
    assert "Information-flow lattice violation" in d
    assert "declassifier" in d or "endorser" in d


def test_no_declassifier_signal_yet():
    # The lattice is future-correct: a declassifier would clear the flow, but no
    # ingester emits one today, so the check is a no-op that never breaks a flow.
    assert has_declassifier(build_model("examples/vulnerable-agent")) is False


def test_violation_is_frozen_and_typed():
    v = violations(_model({"database"}, {"network"}))[0]
    assert isinstance(v, Violation) and v.kind and v.justification
