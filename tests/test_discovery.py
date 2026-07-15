"""M1 zero-config proof: the scan preamble states what autodiscovery found and,
honestly, what a design review does not read."""
from attestral.ingest import build_model
from attestral.model import SystemModel
from attestral.report_terminal import render_discovery, render_scan
from attestral.rules import RuleEngine


def test_discovery_counts_families_and_sources():
    model = build_model("examples/demo-project")
    out = render_discovery(model, "demo", color=False)
    assert "Reviewed 8 components across 2 source files" in out
    assert "4 agent / MCP surface" in out
    assert "4 cloud resources" in out
    assert "not SAST" in out  # the honest scope note is always present


def test_discovery_pluralizes_single_source():
    model = build_model("examples/aws-core-band")
    out = render_discovery(model, "t", color=False)
    assert "across 1 source file:" in out          # singular, no trailing 's'
    assert "10 cloud resources" in out


def test_discovery_empty_model_is_blank():
    assert render_discovery(SystemModel(), "t", color=False) == ""


def test_preamble_appears_above_the_summary_in_a_full_scan():
    model = build_model("examples/demo-project")
    findings = RuleEngine().evaluate(model)
    out = render_scan(model, findings, "demo", color=False)
    reviewed = out.index("Reviewed 8 components")
    summary = out.index("8 components · 13 findings")
    assert reviewed < summary


def test_quiet_scan_omits_the_preamble():
    model = build_model("examples/demo-project")
    findings = RuleEngine().evaluate(model)
    out = render_scan(model, findings, "demo", quiet=True, color=False)
    assert "Reviewed" not in out
