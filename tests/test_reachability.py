"""Reachability-based severity: findings on a walked attack chain carry the
chain and get raised one band, capped at the chain's own severity."""
from pathlib import Path

from attestral.aivss import score
from attestral.evidence import render_markdown
from attestral.ingest import build_model
from attestral.model import Finding, Severity
from attestral.reachability import annotate_reachability
from attestral.report_terminal import render_scan
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _annotated(fixture: str):
    model = build_model(str(EXAMPLES / fixture))
    findings = RuleEngine().evaluate(model)
    notes = annotate_reachability(model, findings)
    return model, findings, notes


def _by_rule(findings, rule_id):
    return next(f for f in findings if f.rule_id == rule_id)


def test_internal_chain_raises_one_band_capped_at_high():
    model, findings, notes = _annotated("internal-attack-path")
    assert notes and "raised" in notes[0]

    # The egress/entry tool: medium -> high, and it carries the walked chain.
    web = _by_rule(findings, "ATL-107")
    assert web.severity is Severity.HIGH
    assert web.escalated_from == "medium"
    assert web.reachability == "internal chain: web -> ops -> web"
    assert web.reachability_role == "entry+impact"

    # The pivot is already critical: annotated, never raised further.
    ops = _by_rule(findings, "ATL-103")
    assert ops.severity is Severity.CRITICAL
    assert ops.escalated_from == ""
    assert ops.reachability_role == "pivot"


def test_internal_chain_never_pushes_past_the_chain_severity():
    # A HIGH finding on an internal (HIGH) chain must stay HIGH - the cap is
    # the chain's own severity, so escalation never outranks the chain.
    model, findings, _ = _annotated("internal-attack-path")
    web_component = next(c for c in model.components if c.name == "web")
    synthetic = Finding(
        rule_id="ATL-TEST", title="t", severity=Severity.HIGH,
        component_id=web_component.id, description="d", recommendation="r",
    )
    annotate_reachability(model, [synthetic])
    assert synthetic.severity is Severity.HIGH
    assert synthetic.escalated_from == ""
    assert synthetic.reachability          # still annotated with the chain


def test_external_chain_raises_high_to_critical():
    _, findings, _ = _annotated("attack-path")
    entry = _by_rule(findings, "ATL-121")
    assert entry.severity is Severity.CRITICAL
    assert entry.escalated_from == "high"
    assert entry.reachability.startswith("external chain:")
    assert entry.reachability_role == "entry"


def test_model_level_findings_are_not_annotated():
    _, findings, _ = _annotated("attack-path")
    for rule_id in ("ATL-210", "ATL-203", "ATL-207"):
        f = _by_rule(findings, rule_id)
        assert f.reachability == ""
        assert f.escalated_from == ""


def test_annotation_is_idempotent():
    model, findings, _ = _annotated("internal-attack-path")
    before = [(f.rule_id, f.severity, f.reachability) for f in findings]
    annotate_reachability(model, findings)   # second pass
    after = [(f.rule_id, f.severity, f.reachability) for f in findings]
    assert before == after


def test_no_chain_means_no_annotation():
    model, findings, notes = _annotated("aws-pack")
    assert notes == []
    assert all(f.reachability == "" and f.escalated_from == "" for f in findings)


def test_terminal_report_renders_the_path_line():
    model, findings, _ = _annotated("internal-attack-path")
    out = render_scan(model, findings, "t", color=False)
    assert "path: internal chain: web -> ops -> web" in out
    assert "raised from medium" in out


def test_markdown_report_carries_the_chain():
    model, findings, _ = _annotated("internal-attack-path")
    md = render_markdown(model, findings, "t")
    assert "**Reachable chain:** internal chain: web -> ops -> web" in md
    assert "severity raised from medium" in md


def test_reachable_finding_gets_full_threat_multiplier():
    model, findings, _ = _annotated("internal-attack-path")
    on_chain = _by_rule(findings, "ATL-107")
    assert score(model, on_chain).threat_multiplier == 1.0
    off_chain = _by_rule(findings, "ATL-203")   # fleet-level, not annotated
    assert score(model, off_chain).threat_multiplier < 1.0
