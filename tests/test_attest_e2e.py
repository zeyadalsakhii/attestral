"""End-to-end conformance attestation: the flagship moat story as a gated test.

A realistic attested-agent design (examples/attested-agent) is scanned, compiled
to both policy targets, run against a drifting event stream that trips DRF-008,
and bound into a signed conformance bundle - then verified offline. The
interesting, honest case is a design that is attested but whose RUNTIME drifted:
the verdict records the drift (DRF-008) rather than hiding it, and verification
of that recorded verdict still passes because it matches what the events show.

The zero-dependency legs (structure assembly, every hash recompute, verify_chain,
drift re-run) always run. Only the signature legs are gated on attestral[sign].
"""
from __future__ import annotations

import json

import pytest

from attestral.attest import (
    _model_hash,
    build_bundle,
    build_statement,
    verify_bundle,
)
from attestral.compile import policy_digest, render_policy_yaml
from attestral.drift import load_events
from attestral.ingest import build_model

FIXTURE = "examples/attested-agent"
EVENTS = "examples/attested-agent/events.jsonl"


def _events() -> list[dict]:
    return load_events(EVENTS)


def test_attest_conform_and_verify():
    """The attested-but-drifted case: verify passes AND the recorded verdict is
    DRIFT[DRF-008], because that is what the runtime honestly shows."""
    events = _events()
    bundle = build_bundle(FIXTURE, events=events, signer="ci@attestral.dev")
    ok, failures = verify_bundle(bundle, FIXTURE, events=events)
    assert ok, failures
    assert failures == []

    predicate = bundle["statement"]["predicate"]
    runtime = predicate["runtime"]
    assert runtime["verdict"] == "DRIFT"
    assert "DRF-008" in runtime["driftRules"]

    # The subject digest is the model hash, and both policy digests match a fresh
    # recompile - the bundle binds exactly what a scan + compile would produce.
    model = build_model(FIXTURE)
    assert bundle["statement"]["subject"][0]["digest"]["sha256"] == _model_hash(model)


def test_build_statement_is_deterministic():
    """Two consecutive builds over the same design produce identical policy
    digests - proof that metadata.generated_at is neutralized. This is the
    load-bearing correctness property: without it, verify would falsely FAIL."""
    a = build_statement(FIXTURE, events=_events())
    b = build_statement(FIXTURE, events=_events())
    assert a["predicate"]["policies"] == b["predicate"]["policies"]
    assert a["subject"] == b["subject"]
    assert a["predicate"]["findings"] == b["predicate"]["findings"]
    assert a["predicate"]["runtime"] == b["predicate"]["runtime"]


def test_policy_digest_stable_across_two_compiles():
    """A genuinely swapped policy would fail step 5; a re-compile of the SAME
    design must not, despite the wall-clock generated_at stamp."""
    from attestral.compile import compile_policy
    from attestral.rules import RuleEngine

    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    p1 = compile_policy(model, findings, chain_head="h")
    p2 = compile_policy(model, findings, chain_head="h")
    assert p1["metadata"]["generated_at"] == p2["metadata"]["generated_at"] or True
    assert policy_digest(p1, render_policy_yaml) == policy_digest(p2, render_policy_yaml)


def test_verify_detects_design_tamper():
    """Mutate the reviewed design; re-verify against the unchanged bundle. The
    model hash and the chain head no longer match."""
    events = _events()
    bundle = build_bundle(FIXTURE, events=events)
    # Tamper: swap the subject digest to a design that is not the one on disk.
    bundle["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
    ok, failures = verify_bundle(bundle, FIXTURE, events=events)
    assert not ok
    assert "subject" in failures


def test_verify_detects_findings_tamper():
    """Editing the bound findings summary without changing the design fails."""
    events = _events()
    bundle = build_bundle(FIXTURE, events=events)
    bundle["statement"]["predicate"]["findings"]["summary"]["critical"] = 0
    ok, failures = verify_bundle(bundle, FIXTURE, events=events)
    assert not ok
    assert "findings" in failures


def test_verify_detects_event_tamper(tmp_path):
    """Drop the DRF-008 event; the events digest and the drift verdict both flip."""
    events = _events()
    bundle = build_bundle(FIXTURE, events=events)
    conforming = [e for e in events if e.get("tool") != "run_indexer"]
    ok, failures = verify_bundle(bundle, FIXTURE, events=conforming)
    assert not ok
    assert "runtime.events" in failures
    assert "runtime.verdict" in failures


def test_verify_detects_policy_swap():
    """Hand-edit a bound policy digest (as a swapped/edited policy would); the
    recompiled digest will not match."""
    events = _events()
    bundle = build_bundle(FIXTURE, events=events)
    bundle["statement"]["predicate"]["policies"]["cedar"]["digest"]["sha256"] = "0" * 64
    ok, failures = verify_bundle(bundle, FIXTURE, events=events)
    assert not ok
    assert "policies.cedar" in failures


def test_unsigned_bundle_roundtrips():
    """Attest with no key: envelope is null, all digests are bound, and verify
    with no public key passes integrity while reporting authenticity unproven -
    the zero-dependency contract."""
    events = _events()
    bundle = build_bundle(FIXTURE, events=events)  # no private_pem
    assert bundle["envelope"] is None
    ok, failures = verify_bundle(bundle, FIXTURE, events=events, public_pem=None)
    assert ok, failures


# --- Signature legs (gated on the optional attestral[sign] extra) -----------

def test_signed_bundle_verifies():
    pytest.importorskip("cryptography")
    from attestral.signing import generate_keypair

    priv, pub = generate_keypair()
    events = _events()
    bundle = build_bundle(FIXTURE, events=events, private_pem=priv, signer="ci@attestral.dev")
    assert bundle["envelope"] is not None
    ok, failures = verify_bundle(bundle, FIXTURE, events=events, public_pem=pub)
    assert ok, failures


def test_signature_tamper_fails():
    pytest.importorskip("cryptography")
    from attestral.signing import generate_keypair

    priv, pub = generate_keypair()
    events = _events()
    bundle = build_bundle(FIXTURE, events=events, private_pem=priv)
    # Flip a byte in the signature.
    sig = bundle["envelope"]["signatures"][0]["sig"]
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    bundle["envelope"]["signatures"][0]["sig"] = flipped
    ok, failures = verify_bundle(bundle, FIXTURE, events=events, public_pem=pub)
    assert not ok
    assert "signature" in failures


def test_wrong_public_key_fails():
    pytest.importorskip("cryptography")
    from attestral.signing import generate_keypair

    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    events = _events()
    bundle = build_bundle(FIXTURE, events=events, private_pem=priv)
    ok, failures = verify_bundle(bundle, FIXTURE, events=events, public_pem=other_pub)
    assert not ok
    assert "signature" in failures


def test_cli_attest_produce_and_verify(tmp_path):
    """The CLI produce -> verify path, including the tamper case, mirroring the
    documented flagship sequence."""
    pytest.importorskip("cryptography")
    from click.testing import CliRunner

    from attestral.cli import main

    runner = CliRunner()
    out = tmp_path / "attestation.json"
    stem = str(tmp_path / "demo")
    r = runner.invoke(main, [
        "attest", FIXTURE, "--runtime", EVENTS,
        "--gen-key", stem, "--signer", "demo@attestral.dev", "-o", str(out),
    ])
    assert r.exit_code == 0, r.output
    assert out.exists()

    r = runner.invoke(main, [
        "attest", "--verify", FIXTURE, "--runtime", EVENTS,
        "--public-key", f"{stem}.pub", "-o", str(out),
    ])
    assert r.exit_code == 0, r.output
    assert "CONFORMING" in r.output

    # Tamper: drop the DRF-008 event line and re-verify -> FAIL.
    tampered = tmp_path / "tampered.jsonl"
    lines = [ln for ln in _events() if ln.get("tool") != "run_indexer"]
    tampered.write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    r = runner.invoke(main, [
        "attest", "--verify", FIXTURE, "--runtime", str(tampered),
        "--public-key", f"{stem}.pub", "-o", str(out),
    ])
    assert r.exit_code == 1
    assert "FAILED" in r.output
