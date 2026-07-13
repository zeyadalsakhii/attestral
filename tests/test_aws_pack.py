"""Coverage for the AWS rule pack (rules/aws_pack.yaml, ATL-027..ATL-054).

Mirrors tests/test_multicloud_rules.py: build a model from the fixture and
assert every new AWS id fires, then guard id uniqueness across the whole
loaded ruleset.
"""
from attestral.ingest import build_model
from attestral.rules import RuleEngine

FIXTURE = "examples/aws-pack"

# Every id the pack ships, ATL-027 through ATL-054 inclusive.
PACK_IDS = {f"ATL-{n:03d}" for n in range(27, 55)}


def _ids():
    model = build_model(FIXTURE)
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_all_aws_pack_rules_fire():
    fired = _ids()
    missing = sorted(PACK_IDS - fired)
    assert not missing, f"pack rules that did not fire: {missing}"


def test_aws_pack_fixture_triggers_no_unexpected_core_rules():
    # The fixture is authored so only pack ids fire; if a core rule starts
    # firing here it means a fixture resource drifted into overlapping a
    # core check, which we want to know about.
    fired = _ids()
    assert fired == PACK_IDS


def test_aws_pack_ids_are_the_expected_band():
    engine = RuleEngine()
    pack_rule_ids = {r["id"] for r in engine.rules if r["id"] in PACK_IDS}
    assert pack_rule_ids == PACK_IDS


def test_no_duplicate_ids_across_all_packs():
    ids = [r["id"] for r in RuleEngine().rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate rule ids across packs: {dupes}"
    assert len(ids) == len(set(ids))


def test_aws_pack_rules_are_well_formed():
    engine = RuleEngine()
    for r in engine.rules:
        if r["id"] not in PACK_IDS:
            continue
        assert r["severity"] in {"critical", "high", "medium", "low"}
        assert str(r["target"]).startswith("aws_")
        assert r.get("match"), f"{r['id']} has no matcher"
        assert r.get("description") and r.get("recommendation")
        assert r.get("frameworks"), f"{r['id']} cites no control"
