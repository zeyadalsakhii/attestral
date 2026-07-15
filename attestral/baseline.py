"""Baseline / diff-aware scanning.

A brownfield repo's first scan can surface hundreds of pre-existing findings, and
a wall of day-one debt gets a scanner uninstalled no matter how good the findings
are. `--baseline` records the current finding set once; later scans then report
only findings NOT in the baseline - the net-new issues a change introduced - so a
team can adopt the tool on a large existing codebase and gate CI on what their PR
actually adds.

A finding's identity is its fingerprint `(rule_id, component_id)` - the same
identity waivers key on, stable across scans of the same design. The baseline is a
small JSON file of those fingerprints; it is meant to be committed.
"""
from __future__ import annotations

import json
from pathlib import Path

from attestral.model import Finding

_VERSION = 1


def fingerprint(f: Finding) -> str:
    """Stable identity of a finding across scans: the rule and the component it
    fired on. Not the message or severity, which can be reworded without the
    underlying issue changing."""
    return f"{f.rule_id}::{f.component_id}"


def write_baseline(path: str | Path, findings: list[Finding]) -> int:
    """Record the fingerprints of `findings` to `path`. Returns the count."""
    fps = sorted({fingerprint(f) for f in findings})
    Path(path).write_text(
        json.dumps({"version": _VERSION, "fingerprints": fps}, indent=2) + "\n"
    )
    return len(fps)


def load_baseline(path: str | Path) -> set[str]:
    """The fingerprints recorded in a baseline file. A missing or malformed file
    yields an empty set (fails open to 'nothing baselined'), never an error."""
    try:
        data = json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError):
        return set()
    fps = data.get("fingerprints") if isinstance(data, dict) else None
    return {str(x) for x in fps} if isinstance(fps, list) else set()


def split_new(
    findings: list[Finding], baseline: set[str]
) -> tuple[list[Finding], list[Finding]]:
    """Partition findings into (net_new, pre_existing) by baseline membership,
    preserving order within each group."""
    new: list[Finding] = []
    known: list[Finding] = []
    for f in findings:
        (known if fingerprint(f) in baseline else new).append(f)
    return new, known
