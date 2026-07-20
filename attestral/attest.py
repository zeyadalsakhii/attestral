"""Verifiable conformance attestation: bind a reviewed design, its compiled
policies, and observed runtime into one signed, offline-checkable claim.

This is the capstone of the moat. A `scan` produces a reviewed design (a
`SystemModel`, findings, and a SHA-256 evidence chain); `compile` turns that
design into runtime policy (mcp-guard and Cedar); `drift` diffs runtime events
against the policy. On their own, each is a live artifact you have to trust the
tool to have produced honestly. This module makes "the running system conforms
to the reviewed design" a claim a THIRD PARTY can verify offline, without
trusting the runtime or the scanner.

The attestation is an in-toto Statement wrapped in a DSSE envelope (the same
envelope Sigstore and in-toto use), signed Ed25519. In one signed object it
binds: the reviewed design (`model_hash`), the review chain head, a digest and
severity summary of the findings, the hash of BOTH compiled policies, and, when
runtime telemetry is supplied, a digest of the events plus the drift verdict.
Verification recomputes every one of those digests from the supplied design (and
re-runs drift on the supplied events) and checks the signature, so ANY tamper - a
changed design, a swapped policy, a doctored event stream - makes verification
FAIL.

Honest framing, kept verbatim across the CLI, the docs, and the site: this is a
TAMPER-EVIDENT, SIGNATURE-BASED CONFORMANCE ATTESTATION, not a formal or
mathematical proof of security. It proves exactly one thing - the runtime
observed matches the design that was reviewed and the policies compiled from it.
It does NOT prove the design is safe, the rule pack is complete, or that no
vulnerability exists; a clean attestation over a weak design is still a weak
design. Conformance is correspondence, not soundness.

Design invariants kept: `cryptography` is the optional `attestral[sign]` extra,
lazy-imported inside `signing.py`, so the STRUCTURE assembly, every hash bind,
`verify_chain`, and every recompute/compare run with zero dependencies. Only the
signature step (`sign_statement` / `verify_envelope`) needs the extra, so an
unsigned bundle - full statement, all digests bound - is produced with no install.
"""
from __future__ import annotations

import hashlib
import json

from attestral import __version__
from attestral.compile import (
    _model_hash,
    compile_policy,
    policy_digest,
    render_cedar,
    render_policy_yaml,
)
from attestral.drift import detect_drift
from attestral.evidence import GENESIS, _SEV_ORDER, audit_chain, verify_chain
from attestral.ingest import build_model
from attestral.reachability import annotate_reachability
from attestral.rules import RuleEngine

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://attestral.dev/attestation/conformance/v1"
VERIFIER_ID = "https://attestral.dev"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _review(path: str) -> tuple:
    """The shared review preamble: the same sequence `scan` and `compile` run, so
    a bundle binds exactly what a scan reports. `annotate_reachability` runs
    before the chain is hashed because it can escalate a finding's severity,
    which changes both the chain head and the compiled deny set - verify must run
    it too or the two paths would diverge."""
    model = build_model(path)
    findings = RuleEngine().evaluate(model)
    annotate_reachability(model, findings)
    chain = audit_chain(findings)
    head = chain[-1]["hash"] if chain else GENESIS
    return model, findings, chain, head


def _findings_digest(findings: list) -> str:
    """SHA-256 over the ORDERED findings. Order is a tamper-evidence invariant
    (it is the order the evidence chain commits to), so it is never sorted."""
    payload = json.dumps([f.to_dict() for f in findings])
    return f"sha256:{_sha256(payload)}"


def _findings_summary(findings: list) -> dict:
    """Severity counts over active findings, plus the waived count - the same
    breakdown `evidence.render_markdown` renders."""
    active = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]
    summary = {sev: 0 for sev in _SEV_ORDER}
    for f in active:
        summary[f.severity.value] = summary.get(f.severity.value, 0) + 1
    summary["waived"] = len(waived)
    return summary


def _drift_findings_digest(findings: list) -> str:
    payload = json.dumps([f.to_dict() for f in findings], sort_keys=True)
    return f"sha256:{_sha256(payload)}"


def _runtime_block(policy: dict, events: list[dict]) -> dict:
    """The runtime predicate: the events digest and the drift verdict.

    `driftRules` is derived from the SET of rule ids so it is order-independent,
    then sorted for a stable rendering. A CONFORM verdict carries an empty list.
    """
    events_digest = _sha256(json.dumps(events, sort_keys=True, default=str))
    drift_findings = detect_drift(policy, events)
    verdict = "CONFORM" if not drift_findings else "DRIFT"
    drift_rules = sorted({f.rule_id for f in drift_findings})
    return {
        "events": {"digest": {"sha256": events_digest}, "count": len(events)},
        "verdict": verdict,
        "driftRules": drift_rules,
        "driftFindingsDigest": _drift_findings_digest(drift_findings),
    }


def build_statement(
    path: str,
    events: list[dict] | None = None,
    signer: str = "",
    version: str = __version__,
    generated_at: str = "",
) -> dict:
    """Assemble the in-toto Statement binding design, policies, and runtime.

    Zero dependencies: this is pure hash binding, no signature. `generated_at`
    and `signer` are recorded, never recomputed by verify (they are excluded from
    every digest and from every equality check). Pass `generated_at` to pin the
    timestamp; the CLI stamps the current UTC time.
    """
    model, findings, chain, head = _review(path)
    policy = compile_policy(model, findings, chain_head=head)

    predicate: dict = {
        "reviewChainHead": head,
        "findings": {
            "digest": _findings_digest(findings),
            "summary": _findings_summary(findings),
        },
        "policies": {
            "mcpGuard": {"digest": {"sha256": policy_digest(policy, render_policy_yaml)}},
            "cedar": {"digest": {"sha256": policy_digest(policy, render_cedar)}},
        },
        "verifier": {"id": VERIFIER_ID, "version": {"attestral": version}},
        "signer": signer,
        "generated_at": generated_at,
    }
    if events is not None:
        predicate["runtime"] = _runtime_block(policy, events)

    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": path, "digest": {"sha256": _model_hash(model)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def build_bundle(
    path: str,
    events: list[dict] | None = None,
    private_pem: str | None = None,
    signer: str = "",
    version: str = __version__,
    generated_at: str = "",
) -> dict:
    """The on-disk bundle: `{statement, envelope}`. Unsigned when no key is given
    (envelope is null, all digests still bound - the zero-dep graceful degrade)."""
    statement = build_statement(
        path, events=events, signer=signer, version=version, generated_at=generated_at
    )
    envelope = None
    if private_pem:
        from attestral.signing import sign_statement

        envelope = sign_statement(statement, private_pem, signer=signer)
    return {"statement": statement, "envelope": envelope}


def verify_bundle(
    bundle: dict,
    path: str,
    events: list[dict] | None = None,
    public_pem: str | None = None,
) -> tuple[bool, list[str]]:
    """Recompute every bound digest from the SUPPLIED design (and re-run drift on
    the supplied events) and compare. Returns (passed, failing_step_names).

    Fail-closed: any mismatch is a failure; `signer` and `generated_at` are read,
    never recomputed. Only the optional signature check touches the crypto extra;
    every other step runs with zero dependencies.
    """
    failures: list[str] = []
    statement = bundle.get("statement") or {}
    predicate = statement.get("predicate") or {}

    # 1. Statement shape - a wrong or absent type/predicateType is a hard fail.
    if statement.get("_type") != STATEMENT_TYPE:
        failures.append("statement.type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        failures.append("statement.predicateType")

    model, findings, chain, head = _review(path)

    # 2. Subject: the model hash recomputed from PATH must match the bound one.
    subject = statement.get("subject") or [{}]
    bound_model_hash = (subject[0].get("digest") or {}).get("sha256") if subject else None
    if bound_model_hash != _model_hash(model):
        failures.append("subject")

    # 3. Review chain: internal integrity, then the head binding.
    if not verify_chain(chain):
        failures.append("reviewChain.integrity")
    if predicate.get("reviewChainHead") != head:
        failures.append("reviewChainHead")

    # 4. Findings: digest + severity summary.
    recomputed_findings = {
        "digest": _findings_digest(findings),
        "summary": _findings_summary(findings),
    }
    if predicate.get("findings") != recomputed_findings:
        failures.append("findings")

    # 5. Policies: recompile and re-digest both renderings (generated_at blanked).
    policy = compile_policy(model, findings, chain_head=head)
    bound_policies = predicate.get("policies") or {}
    if ((bound_policies.get("mcpGuard") or {}).get("digest") or {}).get("sha256") != \
            policy_digest(policy, render_policy_yaml):
        failures.append("policies.mcpGuard")
    if ((bound_policies.get("cedar") or {}).get("digest") or {}).get("sha256") != \
            policy_digest(policy, render_cedar):
        failures.append("policies.cedar")

    # 6. Runtime: recompute the events digest and re-run drift; every field must
    #    match. A bound runtime block cannot be verified without its events.
    bound_runtime = predicate.get("runtime")
    if events is not None:
        recomputed_runtime = _runtime_block(policy, events)
        if bound_runtime is None:
            failures.append("runtime")
        else:
            if (bound_runtime.get("events") or {}) != recomputed_runtime["events"]:
                failures.append("runtime.events")
            if bound_runtime.get("verdict") != recomputed_runtime["verdict"]:
                failures.append("runtime.verdict")
            if bound_runtime.get("driftRules") != recomputed_runtime["driftRules"]:
                failures.append("runtime.driftRules")
            if bound_runtime.get("driftFindingsDigest") != recomputed_runtime["driftFindingsDigest"]:
                failures.append("runtime.driftFindingsDigest")
    elif bound_runtime is not None:
        failures.append("runtime.events")

    # 7. Signature (only when a public key is supplied). With no key, integrity
    #    and recompute still run and authenticity is reported unproven.
    if public_pem is not None:
        from attestral.signing import envelope_payload, verify_envelope

        envelope = bundle.get("envelope")
        if not envelope:
            failures.append("signature")
        else:
            sig_ok = verify_envelope(envelope, public_pem)
            bound_ok = envelope_payload(envelope) == statement
            if not (sig_ok and bound_ok):
                failures.append("signature")

    return (not failures, failures)
