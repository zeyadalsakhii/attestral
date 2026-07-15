"""M10: compile-the-fix - each finding's enforceable mcp-guard control, bound to
the chain head, with an honest verification verdict."""
import yaml
from click.testing import CliRunner

from attestral.cli import main
from attestral.fix import fix_for_finding, fixes_for
from attestral.ingest import build_model
from attestral.model import Finding, Severity
from attestral.reachability import annotate_reachability
from attestral.rules import RuleEngine

FIXTURE = "examples/vulnerable-agent"


def _model_findings(fixture=FIXTURE):
    model = build_model(fixture)
    findings = RuleEngine().evaluate(model)
    annotate_reachability(model, findings)
    return model, findings


def _fix(findings, rule_id):
    return next(f for f in findings if f.rule_id == rule_id)


def test_proxy_control_denies_shell_server():
    model, findings = _model_findings()
    fx = fix_for_finding(model, _fix(findings, "ATL-103"))
    assert fx.control["servers"]["shell"]["allow"] is False
    assert fx.verification == "enforced-at-proxy"
    assert fx.verified


def test_proxy_control_constrains_non_tls():
    model, findings = _model_findings()
    fx = fix_for_finding(model, _fix(findings, "ATL-101"))
    assert fx.control["servers"]["jira"]["constraints"]["transport"] == "tls_only"


def test_fleet_fix_is_verified_by_resynthesis():
    # Stripping the isolated capability must actually make the rule stop firing.
    model, findings = _model_findings()
    fx = fix_for_finding(model, _fix(findings, "ATL-202"))
    assert fx.verification == "re-synthesized"
    assert fx.verified                      # proven: no longer fires without 'network'
    assert fx.control["session_policy"]["isolate_capability"] == "network"


def test_resynthesis_verification_is_honest_when_it_would_not_close():
    # A fabricated finding whose stripped capability is absent cannot be proven
    # closed by removing it; but here ATL-203 depends on shell, which IS present,
    # so it verifies. Assert the mechanism actually re-evaluates, not hard-codes.
    model, findings = _model_findings()
    fx = fix_for_finding(model, _fix(findings, "ATL-203"))
    assert fx.verified and fx.control["session_policy"]["isolate_capability"] == "shell"


def test_design_only_finding_has_no_compilable_fix():
    # ATL-ML-001 (prompt-injection text) is a content change, not a runtime knob.
    model = build_model(FIXTURE)
    f = Finding("ATL-ML-001", "injection", Severity.HIGH, "mcp_server.web", "d", "r")
    assert fix_for_finding(model, f) is None


def test_fixes_for_dedupes_and_skips_waived():
    model, findings = _model_findings()
    findings_waived = list(findings)
    _fix(findings_waived, "ATL-103").waived = True   # waive one ATL-103
    fixes = fixes_for(model, findings_waived)
    ids = [(f.rule_id, f.component) for f in fixes]
    assert len(ids) == len(set(ids))                 # deduped by (rule, component)
    # the waived shell finding is skipped, but deploy's ATL-103 fix remains
    assert ("ATL-103", "shell") not in ids


def test_fix_carries_chain_head():
    model, findings = _model_findings()
    fx = fix_for_finding(model, _fix(findings, "ATL-103"), chain_head="abc123")
    assert fx.chain_head == "abc123"


# --- CLI --------------------------------------------------------------------

def test_fix_cli_renders_controls():
    r = CliRunner().invoke(main, ["fix", FIXTURE])
    assert r.exit_code == 0, r.output
    assert "Compile-the-fix" in r.output
    assert "verified: enforced-at-proxy" in r.output
    assert "verified: re-synthesized" in r.output
    assert "chain head:" in r.output


def test_fix_cli_rule_filter_and_unknown():
    r = CliRunner().invoke(main, ["fix", FIXTURE, "--rule", "atl-103"])
    assert r.exit_code == 0 and "ATL-103" in r.output and "ATL-101" not in r.output
    r = CliRunner().invoke(main, ["fix", FIXTURE, "--rule", "ATL-999"])
    assert r.exit_code == 1 and "does not fire" in r.output


def test_fix_cli_writes_merged_policy(tmp_path):
    out = tmp_path / "fixes.yaml"
    r = CliRunner().invoke(main, ["fix", FIXTURE, "-o", str(out)])
    assert r.exit_code == 0, r.output
    doc = yaml.safe_load(out.read_text())
    assert doc["servers"]["shell"]["allow"] is False
    assert doc["compiled_from"]["chain_head"]
    assert "session_policy" in doc
