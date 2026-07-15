"""Waivers: documented, expiring exceptions to findings.

A waiver suppresses a finding from the fail-closed gate while keeping it in the
evidence chain, tagged with its justification. Accepted risk stays on the
record; it does not disappear. Three fail-safe rules keep the gate honest:

  * a waiver with no justification is ignored (the finding stays active),
  * an expired waiver stops suppressing (the finding comes back), and
  * a pinned waiver whose finding has changed stops suppressing (see below).

So the only way to silence a finding is a current, justified waiver, and an
auditor sees exactly which risks were formally accepted and why.

`attestral accept` turns the acceptance itself into an audit record: it appends
a waiver carrying provenance - who accepted, when, and a content pin
(`finding_sha256`) of the risk as it was accepted (rule, component, severity,
reachable chain). If any of those later change - a rule wave re-rates the
finding, or a new tool completes an attack chain through the component - the
pin stops matching, the acceptance is stale, and the finding comes back. The
provenance is stamped onto the suppressed finding, so the evidence chain
records not just that a risk was accepted but by whom and on what basis.
Hand-written waivers without a pin behave exactly as before.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from attestral.model import Finding

DEFAULT_WAIVER_FILES = (
    "attestral-waivers.yaml",
    "attestral-waivers.yml",
    ".attestral-waivers.yaml",
)


@dataclass
class Waiver:
    rule: str
    component: str = "*"          # "*" matches any component for this rule
    reason: str = ""
    expires: str | None = None    # ISO date (YYYY-MM-DD); None never expires
    # Provenance, written by `attestral accept` (optional on hand-written waivers).
    accepted_by: str = ""         # who accepted the risk, e.g. "Ada L <ada@example.com>"
    accepted_at: str = ""         # ISO date the risk was accepted
    finding_sha256: str = ""      # content pin of the finding as accepted (finding_pin)
    chain_head: str = ""          # evidence-chain head of the review it was accepted on

    def covers(self, finding: Finding) -> bool:
        return self.rule == finding.rule_id and self.component in ("*", finding.component_id)

    def expired(self, today: _dt.date) -> bool:
        if not self.expires:
            return False
        try:
            return _dt.date.fromisoformat(str(self.expires)) < today
        except ValueError:
            return False  # unparseable date is treated as non-expiring


def finding_pin(f: Finding) -> str:
    """Content hash of the risk being accepted: the rule, the component, the
    severity band, and the reachable chain (if any). If any of these change
    after acceptance - a rule wave re-rates the finding, or a new tool
    completes an attack chain through the component - the pin stops matching
    and the acceptance is stale."""
    payload = json.dumps(
        {
            "rule_id": f.rule_id,
            "component_id": f.component_id,
            "severity": f.severity.value,
            "reachability": f.reachability,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def load_waivers(path: str | Path) -> list[Waiver]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    waivers = []
    for w in data.get("waivers", []):
        waivers.append(
            Waiver(
                rule=str(w.get("rule", "")),
                component=str(w.get("component", "*")),
                reason=str(w.get("reason", "")).strip(),
                expires=w.get("expires"),
                accepted_by=str(w.get("accepted_by", "")),
                accepted_at=str(w.get("accepted_at", "")),
                finding_sha256=str(w.get("finding_sha256", "")),
                chain_head=str(w.get("chain_head", "")),
            )
        )
    return waivers


def discover_waivers(scan_path: str | Path) -> Path | None:
    """Look for a waivers file next to the scan target and in the cwd."""
    target = Path(scan_path)
    root = target.parent if target.is_file() else target
    for base in (root, Path(".")):
        for name in DEFAULT_WAIVER_FILES:
            candidate = base / name
            if candidate.is_file():
                return candidate
    return None


def apply_waivers(
    findings: list[Finding],
    waivers: list[Waiver],
    today: _dt.date | None = None,
) -> list[str]:
    """Mark covered findings as waived, in place.

    Returns human-readable notes for waivers that were skipped (no
    justification, expired, or pinned to a finding that has since changed) so
    the caller can surface them.
    """
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    notes: list[str] = []
    for w in waivers:
        if not w.reason:
            notes.append(f"waiver for {w.rule}/{w.component} ignored: no justification given")
            continue
        if w.expired(today):
            notes.append(
                f"waiver for {w.rule}/{w.component} expired on {w.expires}: finding re-activated"
            )
            continue
        for f in findings:
            if not w.covers(f):
                continue
            if w.finding_sha256 and finding_pin(f) != w.finding_sha256:
                context = f"now {f.severity.value}"
                if f.reachability:
                    context += ", on a reachable attack chain"
                notes.append(
                    f"acceptance of {w.rule}/{f.component_id} is stale: the finding "
                    f"changed since it was accepted ({context}) - finding re-activated; "
                    f"re-run `attestral accept` to re-accept the current risk"
                )
                continue
            f.waived = True
            f.waiver_reason = w.reason
            f.waived_by = w.accepted_by
            f.waived_at = w.accepted_at
    return notes


# --------------------------------------------------------------------------
# `attestral accept`: the acceptance itself as an audit record.
# --------------------------------------------------------------------------

def default_identity(cwd: str | Path = ".") -> str:
    """The accepting engineer's identity for the record: git `user.name
    <user.email>` when configured (looked up from `cwd` so repo-local config
    wins), else the OS username."""
    import subprocess

    def _git(key: str) -> str:
        try:
            out = subprocess.run(
                ["git", "config", key],
                capture_output=True, text=True, cwd=str(cwd), timeout=5,
            )
            return out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    name, email = _git("user.name"), _git("user.email")
    if name and email:
        return f"{name} <{email}>"
    return name or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def record_acceptance(
    path: str | Path,
    finding: Finding,
    reason: str,
    *,
    expires: str | None = None,
    by: str = "",
    chain_head: str = "",
    today: _dt.date | None = None,
) -> Waiver:
    """Append a provenance-carrying waiver for `finding` to the waivers file at
    `path`, creating the file if missing. Returns the recorded Waiver.

    The file's leading comment block is preserved; the entry list is rewritten
    as plain YAML (per-entry inline comments do not survive - the `reason`
    field is the durable place for justification).
    """
    reason = reason.strip()
    if not reason:
        raise ValueError("an acceptance needs a justification (reason)")
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    path = Path(path)

    header = ""
    entries: list[dict] = []
    if path.is_file():
        text = path.read_text()
        head: list[str] = []
        for line in text.splitlines():
            if line.strip() == "" or line.lstrip().startswith("#"):
                head.append(line)
            else:
                break
        header = "\n".join(head).rstrip()
        data = yaml.safe_load(text) or {}
        raw = data.get("waivers") or []
        if not isinstance(raw, list):
            raise ValueError(f"{path}: 'waivers' is not a list")
        entries = [dict(e) for e in raw if isinstance(e, dict)]

    w = Waiver(
        rule=finding.rule_id,
        component=finding.component_id,
        reason=reason,
        expires=str(expires) if expires else None,
        accepted_by=by or default_identity(path.parent),
        accepted_at=today.isoformat(),
        finding_sha256=finding_pin(finding),
        chain_head=chain_head,
    )
    entry = {"rule": w.rule, "component": w.component, "reason": w.reason}
    if w.expires:
        entry["expires"] = w.expires
    entry["accepted_by"] = w.accepted_by
    entry["accepted_at"] = w.accepted_at
    entry["finding_sha256"] = w.finding_sha256
    if w.chain_head:
        entry["chain_head"] = w.chain_head
    entries.append(entry)

    body = yaml.dump({"waivers": entries}, default_flow_style=False, sort_keys=False, width=88)
    path.write_text((header + "\n\n" if header else "") + body)
    return w
