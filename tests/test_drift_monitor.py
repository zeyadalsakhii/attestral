"""M13: continuous drift - the streaming DriftMonitor and the `drift --stdin`
sidecar mode. Same detections as batch, but incremental and stateful."""
import json

from click.testing import CliRunner

from attestral.cli import main
from attestral.drift import DriftMonitor

# A minimal compiled policy: one allowed server pinned to a manifest, tight budgets.
POLICY = {
    "servers": {
        "web": {"allow": True, "manifest_sha256": "attested0000",
                "constraints": {"transport": "tls_only"}},
        "shell": {"allow": False, "reason": "denied by ATL-103"},
    },
    "budgets": {"loop_repeat_threshold": 3, "max_calls_per_server": 4},
}


def test_unattested_and_denied_fire_per_event():
    m = DriftMonitor(POLICY)
    assert [f.rule_id for f in m.observe({"server": "ghost", "tool": "x"})] == ["DRF-001"]
    assert [f.rule_id for f in m.observe({"server": "shell", "tool": "x"})] == ["DRF-002"]


def test_runaway_loop_fires_once_when_it_crosses():
    m = DriftMonitor(POLICY)
    ids = []
    for _ in range(6):  # 6 identical consecutive calls, threshold 3
        ids += [f.rule_id for f in m.observe({"server": "web", "tool": "loop", "args": ["a"]})]
    assert ids.count("DRF-006") == 1  # once, not on every event past the threshold


def test_loop_resets_when_the_call_changes():
    m = DriftMonitor(POLICY)
    seen = []
    seq = ["a", "a", "b", "b", "a", "a"]  # max 2 identical in a row, never reaches 3
    for arg in seq:
        seen += [f.rule_id for f in m.observe({"server": "web", "tool": "t", "args": [arg]})]
    assert "DRF-006" not in seen


def test_volume_budget_fires_once():
    m = DriftMonitor(POLICY)
    ids = []
    for _ in range(7):  # budget is 4; vary args so the loop rule stays quiet
        ids += [f.rule_id for f in m.observe({"server": "web", "tool": "t", "args": [str(_)]})]
    assert ids.count("DRF-007") == 1


def test_rugpull_fires_once_per_new_manifest():
    m = DriftMonitor(POLICY)
    ids = []
    for _ in range(3):  # same changed manifest three times -> one alert
        ids += [f.rule_id for f in m.observe({"server": "web", "tool": "t", "manifest_sha256": "changed1"})]
    assert ids.count("DRF-005") == 1
    # a further, different manifest is a new rug-pull
    ids2 = [f.rule_id for f in m.observe({"server": "web", "tool": "t", "manifest_sha256": "changed2"})]
    assert ids2.count("DRF-005") == 1


def test_matching_manifest_is_not_drift():
    m = DriftMonitor(POLICY)
    ids = [f.rule_id for f in m.observe({"server": "web", "tool": "t", "manifest_sha256": "attested0000"})]
    assert "DRF-005" not in ids


def test_stdin_sidecar_streams_drift(tmp_path):
    import yaml
    pol = tmp_path / "pol.yaml"
    pol.write_text(yaml.safe_dump(POLICY))
    stream = "\n".join(json.dumps(e) for e in [
        {"server": "web", "tool": "ok", "args": ["x"]},
        {"server": "ghost", "tool": "x"},
        {"server": "web", "tool": "t", "manifest_sha256": "rugpulled"},
    ]) + "\n"
    r = CliRunner().invoke(main, ["drift", str(pol), "--stdin"], input=stream)
    assert r.exit_code == 0, r.output
    assert "DRF-001" in r.output and "DRF-005" in r.output
    assert "stream ended" in r.output


def test_stdin_fail_on_drift_exits_nonzero(tmp_path):
    import yaml
    pol = tmp_path / "pol.yaml"
    pol.write_text(yaml.safe_dump(POLICY))
    stream = json.dumps({"server": "ghost", "tool": "x"}) + "\n"
    r = CliRunner().invoke(main, ["drift", str(pol), "--stdin", "--fail-on-drift"], input=stream)
    assert r.exit_code == 1
