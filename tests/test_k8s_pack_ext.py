"""Coverage for the Kubernetes hardening pack extension wave (ATL-526..529).

These rules check attributes the kubernetes ingester already emits and that the
existing ATL-501..525 do not cover: second-tier dangerous capabilities, the
deprecated gitRepo (CVE-2024-10220) and flexVolume volume types, and workloads
placed in a control-plane namespace. Fixtures live in examples/k8s-pack-ext/.
"""
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/k8s-pack-ext"

# ATL-526 .. ATL-529 inclusive.
NEW_IDS = {f"ATL-{n}" for n in range(526, 530)}


def _fire(path: str) -> set[str]:
    model = ingest_kubernetes(path, SystemModel())
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_all_ext_rules_fire():
    fired = _fire(FIXTURE)
    missing = NEW_IDS - fired
    assert not missing, f"extension rules never fired: {sorted(missing)}"


def test_ext_ids_registered():
    ids = {r["id"] for r in RuleEngine().rules}
    assert NEW_IDS <= ids


def test_no_duplicate_rule_ids():
    ids = [r["id"] for r in RuleEngine().rules]
    assert len(ids) == len(set(ids))


def test_second_tier_capabilities():
    fired = _fire(f"{FIXTURE}/dangerous-caps.yaml")
    assert "ATL-526" in fired
    # ATL-503's famous-six rule must NOT co-fire on SYS_RAWIO/SYS_TIME.
    assert "ATL-503" not in fired


def test_gitrepo_volume():
    assert "ATL-527" in _fire(f"{FIXTURE}/gitrepo-volume.yaml")


def test_flexvolume():
    assert "ATL-528" in _fire(f"{FIXTURE}/flexvolume.yaml")


def test_control_plane_namespace():
    assert "ATL-529" in _fire(f"{FIXTURE}/kube-system-workload.yaml")


def test_compliant_fixture_triggers_no_extension_rule():
    # Negative case: a hardened workload in a dedicated namespace that adds only
    # NET_BIND_SERVICE and mounts only an emptyDir fires none of ATL-526..529.
    fired = _fire(f"{FIXTURE}/compliant.yaml")
    assert not (NEW_IDS & fired), f"unexpected extension findings: {sorted(NEW_IDS & fired)}"


def test_ingester_emits_matched_attrs():
    # Guardrails: assert the exact attributes these rules match are the ones the
    # ingester actually sets, so a rename in kubernetes.py fails loudly here.
    caps = ingest_kubernetes(f"{FIXTURE}/dangerous-caps.yaml", SystemModel())
    worker = next(c for c in caps.by_type("k8s_container") if c.name == "worker")
    assert "SYS_RAWIO" in worker.attr("_capabilities_add")

    git = ingest_kubernetes(f"{FIXTURE}/gitrepo-volume.yaml", SystemModel())
    assert "gitRepo" in git.by_type("k8s_workload")[0].attr("_volume_types")

    flex = ingest_kubernetes(f"{FIXTURE}/flexvolume.yaml", SystemModel())
    assert "flexVolume" in flex.by_type("k8s_workload")[0].attr("_volume_types")

    ks = ingest_kubernetes(f"{FIXTURE}/kube-system-workload.yaml", SystemModel())
    assert ks.by_type("k8s_workload")[0].attr("namespace") == "kube-system"
