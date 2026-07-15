"""M12: cross-repo fleet modeling - the toxic flow that spans repositories and
that no per-repo scan can see (ATL-213)."""
from click.testing import CliRunner

from attestral.cli import main
from attestral.fleet import build_fleet_model, render_fleet_overview
from attestral.ingest import build_model
from attestral.paths import all_attack_paths
from attestral.rules import RuleEngine

READER = "examples/fleet-repo-reader"   # untrusted input + egress, no shell
RUNNER = "examples/fleet-repo-runner"   # shell only, no input, no egress


def _fleet_ids(*paths):
    model, labels = build_fleet_model(list(paths))
    return {f.rule_id for f in RuleEngine().evaluate(model)}, model, labels


def test_neither_repo_alone_has_an_attack_path():
    for repo in (READER, RUNNER):
        assert all_attack_paths(build_model(repo)) == []
        assert "ATL-213" not in {f.rule_id for f in RuleEngine().evaluate(build_model(repo))}


def test_fleet_completes_the_cross_repo_chain():
    ids, model, labels = _fleet_ids(READER, RUNNER)
    assert "ATL-213" in ids                    # the cross-repo toxic flow
    assert len(all_attack_paths(model)) == 1   # the chain now exists, spanning repos
    assert set(labels) == {"fleet-repo-reader", "fleet-repo-runner"}


def test_components_are_namespaced_by_repo():
    model, _ = build_fleet_model([READER, RUNNER])
    names = {c.name for c in model.tool_surfaces()}
    assert "fleet-repo-reader/web" in names
    assert "fleet-repo-runner/ops" in names
    ids = {c.id for c in model.components}
    assert len(ids) == len(model.components)    # no id collisions across repos


def test_reachability_escalates_because_the_other_repo_completes_the_chain():
    model, _ = build_fleet_model([READER, RUNNER])
    findings = RuleEngine().evaluate(model)
    from attestral.reachability import annotate_reachability
    annotate_reachability(model, findings)
    web = next(f for f in findings if f.rule_id == "ATL-107")   # reader's fetch tool
    assert web.escalated_from == "medium"                       # raised because runner completes it


def test_single_repo_completing_the_chain_does_not_fire_atl213():
    # vulnerable-agent has the whole trifecta in ONE repo: the cross-repo rule
    # must stay silent (its own scan already catches it).
    model, _ = build_fleet_model(["examples/vulnerable-agent"])
    assert "ATL-213" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_two_repos_that_each_self_complete_do_not_fire_atl213():
    # If some single repo completes the chain alone, ATL-213 adds nothing.
    model, _ = build_fleet_model(["examples/vulnerable-agent", READER])
    assert "ATL-213" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_overview_names_the_cross_repo_chain():
    model, labels = build_fleet_model([READER, RUNNER])
    out = render_fleet_overview(model, labels, color=False)
    assert "Fleet: 2 repos" in out
    assert "cross-repo chain: entry [fleet-repo-reader]" in out


def test_fleet_command_end_to_end(tmp_path):
    runner = CliRunner()
    r = runner.invoke(main, ["fleet", READER, RUNNER])
    assert r.exit_code == 0, r.output
    assert "ATL-213" in r.output
    assert "cross-repo chain" in r.output

    r = runner.invoke(main, ["fleet", READER, RUNNER, "--fail-on", "high", "--quiet"])
    assert r.exit_code == 1   # the cross-repo high gate trips


def test_fleet_command_writes_report(tmp_path):
    runner = CliRunner()
    out = tmp_path / "fleetrep"
    r = runner.invoke(main, ["fleet", READER, RUNNER, "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "fleetrep.md").exists()
    import json
    data = json.loads((tmp_path / "fleetrep.json").read_text())
    assert data["repos"] == ["fleet-repo-reader", "fleet-repo-runner"]
    assert any(e["finding"]["rule_id"] == "ATL-213" for e in data["chain"])
