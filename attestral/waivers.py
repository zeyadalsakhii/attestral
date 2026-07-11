"""Waivers: documented, expiring exceptions to findings.

A waiver suppresses a finding from the fail-closed gate while keeping it in the
evidence chain, tagged with its justification. Accepted risk stays on the
record; it does not disappear. Two fail-safe rules keep the gate honest:

  * a waiver with no justification is ignored (the finding stays active), and
  * an expired waiver stops suppressing (the finding comes back).

So the only way to silence a finding is a current, justified waiver, and an
auditor sees exactly which risks were formally accepted and why.
"""
from __future__ import annotations

import datetime as _dt
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

    def covers(self, finding: Finding) -> bool:
        return self.rule == finding.rule_id and self.component in ("*", finding.component_id)

    def expired(self, today: _dt.date) -> bool:
        if not self.expires:
            return False
        try:
            return _dt.date.fromisoformat(str(self.expires)) < today
        except ValueError:
            return False  # unparseable date is treated as non-expiring


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
    justification, or expired) so the caller can surface them.
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
            if w.covers(f):
                f.waived = True
                f.waiver_reason = w.reason
    return notes
