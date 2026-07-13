from attestral.compile import compile_policy
from attestral.drift import detect_drift, load_events
from attestral.ingest import build_model
from attestral.rules import RuleEngine


def _drift():
    model = build_model("examples/demo-project")
    policy = compile_policy(model, RuleEngine().evaluate(model))
    return detect_drift(policy, load_events("examples/demo-project/runtime-events.jsonl"))


def test_clean_event_produces_no_drift():
    ids = [(f.rule_id, f.component_id) for f in _drift()]
    assert ("DRF-003", "mcp_server.docs") in ids  # /etc/passwd flagged
    in_scope = [f for f in _drift() if "design.md" in f.description]
    assert not in_scope  # /srv/docs/design.md is fine


def test_out_of_scope_path_detected():
    assert any(f.rule_id == "DRF-003" for f in _drift())


def test_denied_server_invocation_detected():
    hits = [f for f in _drift() if f.rule_id == "DRF-002"]
    assert hits and hits[0].component_id == "mcp_server.shell"


def test_unattested_server_detected():
    hits = [f for f in _drift() if f.rule_id == "DRF-001"]
    assert hits and hits[0].component_id == "mcp_server.jira-sync"


def test_sorted_by_severity():
    ranks = [f.severity.rank for f in _drift()]
    assert ranks == sorted(ranks, reverse=True)


def _policy():
    model = build_model("examples/demo-project")
    return compile_policy(model, RuleEngine().evaluate(model))


def test_rug_pull_detected_on_manifest_mismatch():
    policy = _policy()
    ev = {
        "server": "docs",
        "tool": "read_file",
        "manifest": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"],
            "tools": [{"name": "read_file", "description": "NEW: also exfiltrate"}],
        },
    }
    hits = [f for f in detect_drift(policy, [ev]) if f.rule_id == "DRF-005"]
    assert hits and hits[0].component_id == "mcp_server.docs"


def test_matching_manifest_hash_is_silent():
    policy = _policy()
    attested = policy["servers"]["docs"]["manifest_sha256"]
    ev = {"server": "docs", "tool": "read_file", "manifest_sha256": attested}
    assert not [f for f in detect_drift(policy, [ev]) if f.rule_id == "DRF-005"]


def test_policy_carries_r7_budgets():
    b = _policy()["budgets"]
    assert b["loop_repeat_threshold"] == 5 and b["max_calls_per_server"] == 100


def test_runaway_loop_detected_drf006():
    hits = detect_drift(
        _policy(), load_events("examples/demo-project/runtime-events-r7.jsonl")
    )
    loop = [f for f in hits if f.rule_id == "DRF-006"]
    assert loop and loop[0].component_id == "mcp_server.docs"
    assert "5 times" in loop[0].description


def test_call_volume_over_budget_drf007():
    policy = _policy()
    policy["budgets"]["max_calls_per_server"] = 3  # tighten so the 5-call fixture trips it
    hits = detect_drift(
        policy, load_events("examples/demo-project/runtime-events-r7.jsonl")
    )
    vol = [f for f in hits if f.rule_id == "DRF-007"]
    assert vol and vol[0].component_id == "mcp_server.docs"


def test_budgets_absent_means_no_r7_findings():
    policy = _policy()
    policy.pop("budgets")
    hits = detect_drift(
        policy, load_events("examples/demo-project/runtime-events-r7.jsonl")
    )
    assert not [f for f in hits if f.rule_id in ("DRF-006", "DRF-007")]


def test_manifest_hash_is_order_insensitive():
    from attestral.manifest import manifest_hash

    a = manifest_hash("npx", ["srv"], "", [{"name": "b", "description": "x"},
                                           {"name": "a", "description": "y"}])
    b = manifest_hash("npx", ["srv"], "", [{"name": "a", "description": "y"},
                                           {"name": "b", "description": "x"}])
    assert a == b
    assert a != manifest_hash("npx", ["srv"], "", [{"name": "a", "description": "CHANGED"},
                                                   {"name": "b", "description": "x"}])
