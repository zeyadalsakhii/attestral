"""Closed-loop drift remediation: the self-healing half of the runtime loop.

`attestral drift` DETECTS runtime divergence from the reviewed design. This proves
the loop is self-correcting: given the drift findings, `remediate_drift` synthesizes
the minimal policy-tightening delta that would have PREVENTED each finding, and the
proof is end-to-end - apply the delta in memory, re-run drift over the SAME events,
and the offending event is now blocked (DRF-002), the original finding gone.

The load-bearing safety principle is asserted at every turn: the delta only ever
NARROWS the policy toward denial. `narrowing.classify(original, tightened)` must be
NARROWING or UNCHANGED, never EXPANSION, so a compromised runtime can never drive
its own policy by widening the design to match the drift.
"""
import copy

import pytest
import yaml

from attestral.compile import compile_policy, render_cedar, render_policy_yaml
from attestral.drift import detect_drift, load_events, remediate_drift
from attestral.ingest import build_model
from attestral.narrowing import classify
from attestral.rules import RuleEngine

WRAPPER = "examples/opaque-wrapper"
AGENT = "examples/attested-agent"


def _policy(path):
    model = build_model(path)
    return compile_policy(model, RuleEngine().evaluate(model))


def _ids(policy, events):
    return [f.rule_id for f in detect_drift(policy, events)]


# --- FLAGSHIP: DRF-008 opaque wrapper, propose -> apply -> re-run blocks --------

def test_flagship_drf008_remediation_narrows_and_blocks():
    original = _policy(WRAPPER)
    assert original["servers"]["toolrunner"]["allow"] is True
    assert original["servers"]["toolrunner"]["capabilities"] == []

    events = load_events(f"{WRAPPER}/runtime-events-malicious.jsonl")
    # 1. the attack trips DRF-008 against the attested, empty-envelope server.
    assert _ids(original, events) == ["DRF-008"]

    # 2. propose the tightening.
    tightened, delta = remediate_drift(original, detect_drift(original, events))
    assert tightened["servers"]["toolrunner"]["allow"] is False
    assert "DRF-008" in tightened["servers"]["toolrunner"]["reason"]
    assert [op["drf_id"] for op in delta] == ["DRF-008"]
    assert delta[0]["before_allow"] is True and delta[0]["after_allow"] is False

    # 3. THE NARROWING GATE: never an expansion.
    res = classify(original, tightened)
    assert res.overall == "narrowing"
    assert res.is_expansion is False

    # 4. THE BLOCK PROOF: re-run drift over the SAME events - the attack invocation
    #    now hits the quarantine and returns DRF-002 (denied), DRF-008 gone.
    rerun = _ids(tightened, events)
    assert "DRF-008" not in rerun
    assert rerun == ["DRF-002"]

    # 5. the original is never mutated.
    assert original["servers"]["toolrunner"]["allow"] is True


def test_flagship_both_targets_reemit_the_denied_entry():
    original = _policy(WRAPPER)
    events = load_events(f"{WRAPPER}/runtime-events-malicious.jsonl")
    tightened, _ = remediate_drift(original, detect_drift(original, events))

    # mcp-guard: parses back as valid YAML with the server denied.
    reparsed = yaml.safe_load(render_policy_yaml(tightened))
    assert reparsed["servers"]["toolrunner"]["allow"] is False

    # cedar: a flipped allow:false propagates to a forbid block.
    cedar = render_cedar(tightened)
    assert 'forbid (\n  principal == MCPServer::"toolrunner"' in cedar


# --- NEGATIVE CONTROL: no drift -> no gratuitous quarantine ---------------------

def test_benign_stream_yields_no_remediation():
    original = _policy(WRAPPER)
    events = load_events(f"{WRAPPER}/runtime-events-benign.jsonl")
    findings = detect_drift(original, events)
    assert "DRF-008" not in [f.rule_id for f in findings]

    tightened, delta = remediate_drift(original, findings)
    assert delta == []
    assert tightened == original
    assert classify(original, tightened).overall == "equal"


# --- CONSTRAINT-DROP TRAP: quarantine must KEEP constraints, not pop them -------

def test_constraint_drop_trap_kept_constraints_is_narrowing():
    # internal-tools carries root_paths + forbid_env_secrets + a manifest pin, and
    # event #4 shells out (DRF-008). Quarantine keeping those constraints is a
    # narrowing; popping them (compile.py's deny path) reads as EXPANSION.
    original = _policy(AGENT)
    events = load_events(f"{AGENT}/events.jsonl")
    assert _ids(original, events) == ["DRF-008"]

    tightened, delta = remediate_drift(original, detect_drift(original, events))
    entry = tightened["servers"]["internal-tools"]
    assert entry["allow"] is False
    # constraints, capabilities and the manifest pin are kept intact.
    assert entry["constraints"]["root_paths"] == ["/srv/agent-data"]
    assert entry["constraints"]["forbid_env_secrets"] is True
    assert entry["capabilities"] == ["filesystem"]
    assert "manifest_sha256" in entry
    assert classify(original, tightened).overall == "narrowing"

    # the trap: a hand-built variant that POPS the constraints classifies EXPANSION.
    popped = copy.deepcopy(tightened)
    popped["servers"]["internal-tools"].pop("constraints")
    assert classify(original, popped).is_expansion is True


# --- DRF-001: unattested server -> deny-only add is a provable narrowing --------

def test_drf001_quarantine_add_is_narrowing_and_flips_to_drf002():
    original = _policy(WRAPPER)
    rogue = [{"server": "rogue", "tool": "run"}]
    assert _ids(original, rogue) == ["DRF-001"]

    tightened, delta = remediate_drift(original, detect_drift(original, rogue))
    assert tightened["servers"]["rogue"]["allow"] is False
    assert delta[0]["before_allow"] is None  # was absent
    assert "re-review" in delta[0]["note"]

    # the deny-only add is NOT an expansion (classify's scoped refinement).
    assert classify(original, tightened).is_expansion is False
    # re-run: the same rogue invocation is now the denied DRF-002.
    assert _ids(tightened, rogue) == ["DRF-002"]


def test_added_allowed_server_is_still_an_expansion():
    # The refinement is scoped to allow:false. An added ALLOWED server stays an
    # expansion a human must review, so the deny-only carve-out cannot be abused.
    base = {"servers": {"a": {"allow": True, "capabilities": []}}}
    widened = {"servers": dict(base["servers"], b={"allow": True, "capabilities": []})}
    assert classify(base, widened).is_expansion is True


# --- BUDGET: DRF-007 clears cleanly, DRF-006 is blocked-not-cleared -------------

def test_drf007_quarantine_clears_on_rerun():
    # A tight per-server budget so ordinary volume trips DRF-007.
    policy = {
        "servers": {"svc": {"allow": True, "capabilities": [], "constraints": {}}},
        "budgets": {"loop_repeat_threshold": 0, "max_calls_per_server": 2},
    }
    events = [{"server": "svc", "tool": f"t{i}", "args": [i]} for i in range(4)]
    assert "DRF-007" in _ids(policy, events)

    tightened, _ = remediate_drift(policy, detect_drift(policy, events))
    assert tightened["servers"]["svc"]["allow"] is False
    assert classify(policy, tightened).overall == "narrowing"
    rerun = _ids(tightened, events)
    # _budget_drift's DRF-007 branch skips non-allowed servers: it clears, and the
    # calls now hit the quarantine as DRF-002.
    assert "DRF-007" not in rerun
    assert set(rerun) == {"DRF-002"}


def test_drf006_quarantine_blocks_but_alarm_persists():
    # A runaway identical-call loop. Quarantine denies the server (each call is now
    # DRF-002), but _budget_drift's DRF-006 branch has no allow-filter, so the loop
    # alarm co-fires on re-run. The op note states this honestly.
    policy = {
        "servers": {"svc": {"allow": True, "capabilities": [], "constraints": {}}},
        "budgets": {"loop_repeat_threshold": 2, "max_calls_per_server": 100},
    }
    events = [{"server": "svc", "tool": "run", "args": ["x"]} for _ in range(3)]
    assert "DRF-006" in _ids(policy, events)

    tightened, delta = remediate_drift(policy, detect_drift(policy, events))
    assert tightened["servers"]["svc"]["allow"] is False
    assert classify(policy, tightened).overall == "narrowing"
    note = next(op["note"] for op in delta if op["drf_id"] == "DRF-006")
    assert "alarm persists" in note
    rerun = _ids(tightened, events)
    assert "DRF-002" in rerun
    assert "DRF-006" in rerun  # the documented blocked-not-cleared behavior


# --- DRF-002: already denied is a terminal no-op --------------------------------

def test_drf002_is_a_noop():
    policy = {"servers": {"d": {"allow": False, "reason": "denied", "capabilities": []}}}
    events = [{"server": "d", "tool": "run"}]
    assert _ids(policy, events) == ["DRF-002"]
    tightened, delta = remediate_drift(policy, detect_drift(policy, events))
    assert delta == []
    assert tightened == policy


# --- FAIL-CLOSED GUARD: any synthesized expansion is refused, never emitted ------

def test_fail_closed_guard_refuses_a_widening_delta(monkeypatch):
    # If a future op ever widened the policy (added an allowed server, re-pinned a
    # rug-pull, added a capability), the internal narrowing self-check must refuse
    # to emit it. Force _tighten_for to widen and assert the guard raises.
    import attestral.drift as drift_mod

    def _widen(rule_id, name, servers, finding):
        servers[name] = {"allow": True, "capabilities": ["shell"]}  # a widening
        return {"server": name, "drf_id": rule_id, "action": "widen",
                "before_allow": None, "after_allow": True, "reason": "bad", "note": ""}

    monkeypatch.setattr(drift_mod, "_tighten_for", _widen)
    original = _policy(WRAPPER)
    events = load_events(f"{WRAPPER}/runtime-events-malicious.jsonl")
    with pytest.raises(RuntimeError, match="widens the policy"):
        remediate_drift(original, detect_drift(original, events))


def test_widening_shortcuts_each_classify_as_expansion():
    # The three shortcuts the design forbids, each independently caught by the same
    # gate that the fail-closed self-check uses.
    original = _policy(WRAPPER)
    tr = original["servers"]["toolrunner"]

    add_cap = copy.deepcopy(original)
    add_cap["servers"]["toolrunner"]["capabilities"] = ["shell"]
    assert classify(original, add_cap).is_expansion is True

    repin = copy.deepcopy(original)
    repin["servers"]["toolrunner"]["manifest_sha256"] = "deadbeef" * 8
    assert classify(original, repin).is_expansion is True

    orig_agent = _policy(AGENT)
    widen_root = copy.deepcopy(orig_agent)
    widen_root["servers"]["internal-tools"]["constraints"]["root_paths"] = ["/", "/srv/agent-data"]
    assert classify(orig_agent, widen_root).is_expansion is True
    assert tr["capabilities"] == []  # original untouched
