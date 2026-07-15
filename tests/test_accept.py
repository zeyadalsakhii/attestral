"""`attestral accept`: risk acceptance as a provenance-carrying audit record,
pinned to the finding as accepted and stale the moment the risk changes."""
import datetime as dt
import json

from click.testing import CliRunner

from attestral.cli import main
from attestral.model import Finding, Severity
from attestral.waivers import (
    Waiver,
    apply_waivers,
    finding_pin,
    load_waivers,
    record_acceptance,
)

# A fetch tool (entry+impact) and a shell tool (pivot): a complete internal
# chain, so ATL-107 on `web` is raised medium -> high with a reachable chain.
CHAIN_MCP = json.dumps({
    "mcpServers": {
        "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "ops": {"command": "bash", "args": ["-c", "mcp-shell-server --serve"]},
    }
})
# The same design without the pivot: no chain, ATL-107 stays medium.
NO_CHAIN_MCP = json.dumps({
    "mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}
})


def _f(sev: Severity = Severity.MEDIUM, reachability: str = "") -> Finding:
    return Finding("ATL-107", "outbound access", sev, "mcp_server.web", "d", "r",
                   reachability=reachability)


# --- the pin -----------------------------------------------------------------

def test_pin_is_deterministic_and_risk_sensitive():
    assert finding_pin(_f()) == finding_pin(_f())
    assert finding_pin(_f(Severity.MEDIUM)) != finding_pin(_f(Severity.HIGH))
    assert finding_pin(_f()) != finding_pin(_f(reachability="internal chain: web -> ops -> web"))


def test_pinned_waiver_suppresses_and_stamps_provenance(tmp_path):
    w = record_acceptance(tmp_path / "w.yaml", _f(), "scoped allowlist, SEC-42",
                          by="Ada L <ada@example.com>", today=dt.date(2026, 7, 15))
    f = _f()
    notes = apply_waivers([f], [w])
    assert notes == []
    assert f.waived
    assert f.waived_by == "Ada L <ada@example.com>"
    assert f.waived_at == "2026-07-15"


def test_stale_pin_reactivates_the_finding(tmp_path):
    w = record_acceptance(tmp_path / "w.yaml", _f(Severity.MEDIUM), "ok", by="Ada")
    changed = _f(Severity.HIGH, reachability="internal chain: web -> ops -> web")
    notes = apply_waivers([changed], [w])
    assert not changed.waived
    assert changed.waived_by == ""
    assert notes and "stale" in notes[0]
    assert "now high, on a reachable attack chain" in notes[0]


def test_unpinned_handwritten_waiver_still_works_unchanged():
    f = _f(Severity.HIGH, reachability="internal chain: web -> ops -> web")
    apply_waivers([f], [Waiver(rule="ATL-107", component="*", reason="hand-written")])
    assert f.waived and f.waived_by == ""


def test_provenance_lands_in_the_evidence_chain(tmp_path):
    from attestral.evidence import audit_chain
    w = record_acceptance(tmp_path / "w.yaml", _f(), "on the record",
                          by="Ada L <ada@example.com>", today=dt.date(2026, 7, 15))
    f = _f()
    apply_waivers([f], [w])
    entry = audit_chain([f])[0]["finding"]
    assert entry["waived_by"] == "Ada L <ada@example.com>"
    assert entry["waived_at"] == "2026-07-15"


# --- the recorder ------------------------------------------------------------

def test_record_acceptance_roundtrips_through_load(tmp_path):
    p = tmp_path / "attestral-waivers.yaml"
    record_acceptance(p, _f(), "reason one", expires="2026-12-31",
                      by="Ada", chain_head="abc123", today=dt.date(2026, 7, 15))
    loaded = load_waivers(p)
    assert len(loaded) == 1
    w = loaded[0]
    assert (w.rule, w.component) == ("ATL-107", "mcp_server.web")
    assert w.expires == "2026-12-31"
    assert (w.accepted_by, w.accepted_at) == ("Ada", "2026-07-15")
    assert w.finding_sha256 == finding_pin(_f())
    assert w.chain_head == "abc123"


def test_record_acceptance_appends_and_preserves_header_comments(tmp_path):
    p = tmp_path / "attestral-waivers.yaml"
    p.write_text("# keep this scaffold comment\n# and this one\n\nwaivers: []\n")
    record_acceptance(p, _f(), "first", by="Ada")
    record_acceptance(p, _f(Severity.HIGH), "second", by="Ada")
    text = p.read_text()
    assert text.startswith("# keep this scaffold comment\n# and this one")
    assert [w.reason for w in load_waivers(p)] == ["first", "second"]


def test_record_acceptance_refuses_an_empty_reason(tmp_path):
    try:
        record_acceptance(tmp_path / "w.yaml", _f(), "   ")
    except ValueError as exc:
        assert "justification" in str(exc)
    else:
        raise AssertionError("empty reason must be refused")


# --- end-to-end through the CLI ----------------------------------------------

def _repo(tmp_path, mcp: str) -> str:
    (tmp_path / ".mcp.json").write_text(mcp)
    return str(tmp_path)


def test_accept_then_scan_suppresses_with_provenance(tmp_path):
    repo = _repo(tmp_path, CHAIN_MCP)
    runner = CliRunner()
    r = runner.invoke(main, ["accept", repo, "atl-107", "mcp_server.web",
                             "-r", "allowlisted to two internal hosts, SEC-42",
                             "--by", "Test Engineer <t@example.com>"])
    assert r.exit_code == 0, r.output
    assert "severity high, on a reachable attack chain" in r.output

    r = runner.invoke(main, ["scan", repo])
    assert r.exit_code == 0, r.output
    assert "waived (1)" in r.output
    assert "accepted by Test Engineer <t@example.com>" in r.output


def test_design_change_stales_the_acceptance(tmp_path):
    repo = _repo(tmp_path, CHAIN_MCP)
    runner = CliRunner()
    r = runner.invoke(main, ["accept", repo, "ATL-107", "mcp_server.web",
                             "-r", "ok", "--by", "Test Engineer"])
    assert r.exit_code == 0, r.output

    # Removing the pivot dissolves the chain: ATL-107 drops back to medium,
    # the pin no longer matches, and the acceptance must stop suppressing.
    (tmp_path / ".mcp.json").write_text(NO_CHAIN_MCP)
    r = runner.invoke(main, ["scan", repo])
    assert "stale" in r.output
    assert "waived" not in r.output
    assert "MEDIUM (1)" in r.output


def test_accept_unknown_finding_fails_with_candidates(tmp_path):
    repo = _repo(tmp_path, CHAIN_MCP)
    runner = CliRunner()
    r = runner.invoke(main, ["accept", repo, "ATL-107", "mcp_server.nope", "-r", "x"])
    assert r.exit_code == 1
    assert "currently fires on: mcp_server.web" in r.output

    r = runner.invoke(main, ["accept", repo, "ATL-999", "mcp_server.web", "-r", "x"])
    assert r.exit_code == 1
    assert "does not fire" in r.output
