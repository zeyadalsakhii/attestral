"""TerraGoat regression suite (real-world cloud corpus).

Bridgecrew's deliberately-vulnerable Terraform, vendored at
research/terragoat, is the one corpus in the repo written by a third party
to be misconfigured - ground truth we did not author. It pins two promises
at once:

* a detection floor: every rule that fires on TerraGoat today keeps firing
  (a floor, not a ceiling - the HCL resolver cannot yet see through `var.`
  indirection, so counts only ever grow);
* idiom honesty: the patterns every real repo shares stay quiet - a
  world-open *egress* is not "open to the world" (the ATL-002 direction
  regression), and agentic rules never fire on a pure-IaC repo.

Skipped when the corpus is absent: research/ is untracked by design.
"""
from collections import Counter
from pathlib import Path

import pytest

from attestral.ingest import build_model
from attestral.rules import RuleEngine

CORPUS = Path(__file__).resolve().parents[1] / "research" / "terragoat" / "terraform"

pytestmark = pytest.mark.skipif(
    not CORPUS.is_dir(),
    reason="vendored TerraGoat corpus not present (research/ is untracked)",
)

# Observed on the pinned vendored checkout; TerraGoat is frozen, so any
# change here is a change in attestral, not in the corpus.
COMPONENT_COUNTS = {"aws": 64, "azure": 51, "gcp": 11}
DETECTION_FLOOR = {
    "aws": {"ATL-002", "ATL-004", "ATL-007", "ATL-010", "ATL-017", "ATL-021",
            "ATL-035", "ATL-045"},
    "azure": {"ATL-307", "ATL-308", "ATL-314"},
    "gcp": {"ATL-401", "ATL-402", "ATL-405", "ATL-407", "ATL-420"},
}


@pytest.fixture(scope="module")
def scans():
    engine = RuleEngine()
    out = {}
    for prov in DETECTION_FLOOR:
        model = build_model(str(CORPUS / prov))
        out[prov] = (model, engine.evaluate(model))
    return out


@pytest.mark.parametrize("prov", sorted(DETECTION_FLOOR))
def test_ingestion_is_stable(scans, prov):
    model, _ = scans[prov]
    assert len(model.components) == COMPONENT_COUNTS[prov]


@pytest.mark.parametrize("prov", sorted(DETECTION_FLOOR))
def test_detection_floor_holds(scans, prov):
    _, findings = scans[prov]
    fired = Counter(f.rule_id for f in findings)
    missing = DETECTION_FLOOR[prov] - set(fired)
    assert not missing, f"rules stopped firing on TerraGoat {prov}: {sorted(missing)}"


def test_atl_002_matches_exactly_the_world_open_ingress(scans):
    # ATL-002 must fire on precisely the components whose *ingress* admits the
    # world - no more (the egress idiom), no fewer (the true positives).
    model, findings = scans["aws"]
    world_ingress = {
        c.id for c in model.components
        if "0.0.0.0/0" in (c.attr("_ingress_cidr_blocks") or [])
    }
    fired_on = {f.component_id for f in findings if f.rule_id == "ATL-002"}
    assert fired_on == world_ingress
    assert "aws_security_group.web-node" in fired_on  # the genuine open-SSH/HTTP SG


def test_world_open_egress_rule_is_not_a_finding(scans):
    # The original false-positive shape: aws_security_group_rule.egress with
    # type = "egress" and cidr_blocks = ["0.0.0.0/0"] - the near-universal
    # default-outbound idiom. It must stay on record (union attr) but never
    # produce an "open to the world" finding.
    model, findings = scans["aws"]
    rule = model.get("aws_security_group_rule.egress")
    assert rule is not None, "TerraGoat's egress rule resource disappeared from the model"
    assert rule.attr("_egress_cidr_blocks") == ["0.0.0.0/0"]
    assert rule.attr("_ingress_cidr_blocks") is None
    assert not any(
        f.component_id == rule.id and f.rule_id == "ATL-002" for f in findings
    )


@pytest.mark.parametrize("prov", sorted(DETECTION_FLOOR))
def test_agentic_rules_stay_silent_on_pure_iac(scans, prov):
    # TerraGoat contains no agent, MCP server, or prompt surface, so the
    # agentic and cross-boundary bands (ATL-1xx/2xx) must produce nothing -
    # a real-world false-positive read for the moat rules.
    _, findings = scans[prov]
    agentic = sorted(
        f.rule_id for f in findings
        if f.rule_id.startswith("ATL-1") or f.rule_id.startswith("ATL-2")
    )
    assert agentic == [], f"agentic rules fired on cloud-only TerraGoat {prov}: {agentic}"
