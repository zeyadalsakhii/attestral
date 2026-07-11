import datetime as dt
import json

from attestral.model import Finding, Severity
from attestral.sarif import render_sarif
from attestral.model import SystemModel
from attestral.waivers import Waiver, apply_waivers, load_waivers


def _findings():
    return [
        Finding("ATL-001", "public bucket", Severity.CRITICAL, "aws_s3.a", "d", "r"),
        Finding("ATL-005", "no encryption", Severity.MEDIUM, "aws_db.b", "d", "r"),
        Finding("ATL-005", "no encryption", Severity.MEDIUM, "aws_db.c", "d", "r"),
    ]


def test_waiver_suppresses_matching_finding():
    f = _findings()
    apply_waivers(f, [Waiver(rule="ATL-001", component="aws_s3.a", reason="accepted, JIRA-1")])
    waived = [x for x in f if x.waived]
    assert len(waived) == 1
    assert waived[0].rule_id == "ATL-001"
    assert waived[0].waiver_reason == "accepted, JIRA-1"


def test_wildcard_component_waives_all_for_rule():
    f = _findings()
    apply_waivers(f, [Waiver(rule="ATL-005", component="*", reason="platform-managed")])
    assert sum(1 for x in f if x.waived) == 2  # both ATL-005 findings


def test_waiver_without_reason_is_ignored():
    f = _findings()
    notes = apply_waivers(f, [Waiver(rule="ATL-001", component="aws_s3.a", reason="")])
    assert not any(x.waived for x in f)  # fail-safe: stays active
    assert notes and "no justification" in notes[0]


def test_expired_waiver_does_not_suppress():
    f = _findings()
    notes = apply_waivers(
        f,
        [Waiver(rule="ATL-001", component="aws_s3.a", reason="temp", expires="2020-01-01")],
        today=dt.date(2026, 7, 11),
    )
    assert not any(x.waived for x in f)  # re-activated
    assert notes and "expired" in notes[0]


def test_future_expiry_still_suppresses():
    f = _findings()
    apply_waivers(
        f,
        [Waiver(rule="ATL-001", component="aws_s3.a", reason="temp", expires="2030-01-01")],
        today=dt.date(2026, 7, 11),
    )
    assert any(x.waived for x in f)


def test_load_waivers_from_yaml(tmp_path):
    p = tmp_path / "attestral-waivers.yaml"
    p.write_text(
        "waivers:\n"
        "  - rule: ATL-001\n"
        "    component: aws_s3.a\n"
        "    reason: accepted risk, ticket SEC-9\n"
    )
    waivers = load_waivers(p)
    assert len(waivers) == 1
    assert waivers[0].rule == "ATL-001"
    assert waivers[0].reason == "accepted risk, ticket SEC-9"


def test_waived_finding_becomes_sarif_suppression():
    f = _findings()
    apply_waivers(f, [Waiver(rule="ATL-001", component="aws_s3.a", reason="accepted, JIRA-1")])
    doc = json.loads(render_sarif(SystemModel(), f, "t"))
    suppressed = [r for r in doc["runs"][0]["results"] if "suppressions" in r]
    assert len(suppressed) == 1
    assert suppressed[0]["suppressions"][0]["justification"] == "accepted, JIRA-1"
    # non-waived results carry no suppression
    assert all("suppressions" not in r for r in doc["runs"][0]["results"] if r["ruleId"] != "ATL-001")


def test_waiver_reason_is_in_the_evidence_chain():
    from attestral.evidence import audit_chain
    f = _findings()
    apply_waivers(f, [Waiver(rule="ATL-001", component="aws_s3.a", reason="on the record")])
    chain = audit_chain(f)
    entry = next(e for e in chain if e["finding"]["rule_id"] == "ATL-001")
    assert entry["finding"]["waived"] is True
    assert entry["finding"]["waiver_reason"] == "on the record"
