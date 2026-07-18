"""The false-positive budget (M3): per-rule confidence and --min-confidence.

Recall says "we catch the real ones"; the FP-budget says "and we don't cry
wolf." Three properties are gated so the tool stays safe to leave on in CI:

  - every deterministic finding is high-confidence (structural, 0 FP on benign),
  - the ML tier's confidence tracks its probability (a borderline hit is low),
  - --min-confidence high on the benign corpus yields ZERO findings - the
    CI-safe set is genuinely quiet.

The benign corpus itself is the evaluation harness's benign cases, reused here
so the FP-budget contract and the recall contract are graded on the same
designs.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from attestral.cli import main
from attestral.ml import _confidence
from attestral.model import CONFIDENCE_RANK, Finding, Severity
from attestral.rules import RuleEngine
from evaluation.score import _case_model, _with_world_writable

REPO = Path(__file__).resolve().parents[1]
DEMO = str(REPO / "examples" / "demo-project")           # fires the low-confidence ATL-201
CASES = yaml.safe_load((REPO / "evaluation" / "cases.yaml").read_text())


def _finding(confidence: str) -> Finding:
    return Finding(
        rule_id="ATL-X", title="t", severity=Severity.HIGH, component_id="c",
        description="d", recommendation="r", confidence=confidence,
    )


# --- meets_confidence ordering -------------------------------------------------

def test_confidence_ranks_high_over_low():
    assert CONFIDENCE_RANK["high"] > CONFIDENCE_RANK["medium"] > CONFIDENCE_RANK["low"]


def test_meets_confidence_is_at_or_above_floor():
    assert _finding("high").meets_confidence("low")
    assert _finding("high").meets_confidence("high")
    assert _finding("medium").meets_confidence("medium")
    assert not _finding("low").meets_confidence("medium")
    assert not _finding("medium").meets_confidence("high")


def test_unknown_confidence_fails_open_to_high():
    # An unlabelled finding must not be silently filtered - default to high so
    # --min-confidence never drops something it can't classify.
    assert _finding("bogus").meets_confidence("high")


# --- deterministic rules are high by contract ---------------------------------

def test_deterministic_findings_default_high():
    engine = RuleEngine()
    findings = engine.evaluate(_case_model({"path": "examples/demo-project"}))
    assert findings, "expected demo-project to raise findings"
    # Every deterministic finding is high unless the rule explicitly opts down.
    opted_down = {"ATL-201"}   # the only advisory marked confidence: low
    for f in findings:
        if f.rule_id in opted_down:
            assert f.confidence == "low"
        else:
            assert f.confidence == "high", f"{f.rule_id} is not high-confidence"


# --- ML tier confidence tracks probability ------------------------------------

def test_ml_confidence_bands_track_probability():
    assert _confidence(0.95) == "high"
    assert _confidence(0.90) == "high"
    assert _confidence(0.80) == "medium"
    assert _confidence(0.70) == "medium"
    assert _confidence(0.69) == "low"
    assert _confidence(0.10) == "low"


# --- the gated FP-budget contract: high-confidence set is 0 on benign ----------

def test_high_confidence_set_is_zero_on_benign_corpus():
    engine = RuleEngine()
    noisy = {}
    for case in CASES.get("benign", []):
        with _with_world_writable(case):
            model = _case_model(case)
        high = [f for f in engine.evaluate(model) if f.meets_confidence("high")]
        if high:
            noisy[case["id"]] = sorted(f.rule_id for f in high)
    assert not noisy, f"--min-confidence high is not quiet on benign designs: {noisy}"


# --- CLI integration: the filter drops the low-confidence advisory -------------

def test_min_confidence_filters_low_and_reports_count():
    runner = CliRunner()
    default = runner.invoke(main, ["scan", DEMO])
    assert default.exit_code == 0
    assert "ATL-201" in default.output          # low-confidence advisory prints by default

    filtered = runner.invoke(main, ["scan", DEMO, "--min-confidence", "medium"])
    assert filtered.exit_code == 0
    assert "ATL-201" not in filtered.output     # ...and is filtered by a medium floor
    assert "lower-confidence" in filtered.output  # the filter count is reported


def test_min_confidence_labels_low_findings_in_report():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", DEMO])
    assert result.exit_code == 0
    # The low-confidence advisory carries a visible tag; high-confidence findings
    # stay untagged so default output is not cluttered.
    assert "(confidence: low)" in result.output
