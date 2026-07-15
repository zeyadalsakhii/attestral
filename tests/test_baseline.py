"""Baseline / diff-aware scanning (M3): record once, then report only net-new."""
import json

from click.testing import CliRunner

from attestral.baseline import fingerprint, load_baseline, split_new, write_baseline
from attestral.cli import main
from attestral.model import Finding, Severity


def _f(rule: str, comp: str) -> Finding:
    return Finding(rule_id=rule, title=rule, severity=Severity.HIGH,
                   component_id=comp, description="d", recommendation="r")


def test_fingerprint_is_rule_and_component():
    assert fingerprint(_f("ATL-103", "mcp_server.ops")) == "ATL-103::mcp_server.ops"


def test_write_then_load_roundtrips(tmp_path):
    p = tmp_path / "bl.json"
    n = write_baseline(p, [_f("ATL-103", "a"), _f("ATL-107", "b"), _f("ATL-103", "a")])
    assert n == 2  # duplicate collapses
    assert load_baseline(p) == {"ATL-103::a", "ATL-107::b"}


def test_load_missing_or_malformed_is_empty(tmp_path):
    assert load_baseline(tmp_path / "nope.json") == set()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert load_baseline(bad) == set()


def test_split_new_partitions_by_baseline():
    findings = [_f("ATL-103", "a"), _f("ATL-107", "b"), _f("ATL-202", "model")]
    new, known = split_new(findings, {"ATL-103::a"})
    assert [f.rule_id for f in known] == ["ATL-103"]
    assert [f.rule_id for f in new] == ["ATL-107", "ATL-202"]


# --- end-to-end through the CLI --------------------------------------------

def _repo(tmp_path, mcp: str):
    (tmp_path / ".mcp.json").write_text(mcp)
    return str(tmp_path)


def test_first_run_records_baseline(tmp_path):
    repo = _repo(tmp_path, '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]}}}')
    bl = tmp_path / "bl.json"
    res = CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl)])
    assert res.exit_code == 0
    assert "baseline recorded" in res.output
    assert bl.exists()
    assert "ATL-103::mcp_server.ops" in json.loads(bl.read_text())["fingerprints"]


def test_unchanged_rescan_shows_no_net_new(tmp_path):
    repo = _repo(tmp_path, '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]}}}')
    bl = tmp_path / "bl.json"
    CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl)])  # record
    res = CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl)])
    assert res.exit_code == 0
    assert "showing 0 net-new" in res.output
    assert "ATL-103" not in res.output  # pre-existing finding is hidden


def test_new_finding_surfaces_and_gates(tmp_path):
    repo = _repo(tmp_path, '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]}}}')
    bl = tmp_path / "bl.json"
    CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl)])  # record ATL-103
    # add an outbound-fetch server: introduces net-new findings (incl. fleet-level)
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]},'
        ' "web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}'
    )
    res = CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl), "--fail-on", "high"])
    assert "ATL-107" in res.output   # the net-new server finding
    assert "ATL-103" not in res.output  # baselined, still hidden
    assert res.exit_code == 1        # gate fires on the net-new high finding


def test_update_baseline_rerecords(tmp_path):
    repo = _repo(tmp_path, '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]}}}')
    bl = tmp_path / "bl.json"
    CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl)])
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]},'
        ' "web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}'
    )
    res = CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl), "--update-baseline"])
    assert "baseline recorded" in res.output
    # web's finding is now in the baseline, so a plain rescan shows nothing net-new
    res2 = CliRunner().invoke(main, ["scan", repo, "--baseline", str(bl)])
    assert "showing 0 net-new" in res2.output
