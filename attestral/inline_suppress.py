"""Inline suppression: a one-line comment in a config waives a finding.

The waiver file (`waivers.py`) is the heavyweight path for accepted risk -
expiring, provenance-pinned, authored deliberately. This is the lightweight
one for the everyday false positive: drop a marker in the config that produced
the finding and it is waived in place, no separate file to open.

    "web": { "command": "uvx", "args": ["mcp-server-fetch"] }  // attestral:ignore ATL-107 reason: internal-only

A suppressed finding is *waived, not deleted*. It stays in the evidence chain,
tagged with the marker's file and reason, exactly like a waiver-file entry, so
an auditor still sees which risks were set aside and why. That keeps the
tamper-evident chain honest: silence always has a recorded cause.

Matching is by (rule id, source file): a marker in the file a finding came
from, naming that finding's rule, suppresses it. That is deliberately
file-scoped - our findings key off components and files, not source lines - so
a marker suppresses that rule for that file. Fail-safe throughout: a marker
with no matching finding does nothing, a marker in a file the scan did not read
does nothing, and an already-waived finding is left as the waiver file set it.
"""
from __future__ import annotations

import re
from pathlib import Path

from attestral.model import Finding

# `attestral:ignore ATL-107` or `attestral:ignore ATL-107 reason: <text>`.
# Comment-syntax agnostic: the marker is matched as a substring, so it works
# behind #, //, or /* */ in whatever format the config uses.
_MARKER = re.compile(
    r"attestral:ignore\s+(ATL-[A-Z0-9-]+)(?:\s+reason:\s*(.*))?",
    re.IGNORECASE,
)


def markers_in(text: str) -> dict[str, str]:
    """Map each suppressed rule id to its reason for one file's text. Last
    marker for a rule wins; a bare marker maps to an empty reason."""
    out: dict[str, str] = {}
    for m in _MARKER.finditer(text):
        rule = m.group(1).upper()
        reason = (m.group(2) or "").strip()
        # A reason captured from a /* ... */ block should not swallow the closer.
        reason = reason.split("*/")[0].strip()
        out[rule] = reason
    return out


def apply_inline_suppressions(findings: list[Finding]) -> list[str]:
    """Waive findings whose source file carries a matching inline marker, in
    place. Returns one human-readable note per suppression."""
    notes: list[str] = []
    cache: dict[str, dict[str, str]] = {}
    for f in findings:
        if f.waived or not f.source:
            continue
        path = Path(f.source)
        if f.source not in cache:
            try:
                cache[f.source] = markers_in(path.read_text(errors="replace"))
            except OSError:
                cache[f.source] = {}          # e.g. "system model", not a real file
        marker_reason = cache[f.source].get(f.rule_id)
        if marker_reason is None:
            continue
        f.waived = True
        f.waiver_reason = marker_reason or "inline suppression"
        f.waived_by = f"inline: {path.name}"
        notes.append(
            f"{f.rule_id} on {f.component_id} suppressed inline ({path.name})"
        )
    return notes
