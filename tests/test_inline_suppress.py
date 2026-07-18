"""Inline suppression: a one-line marker in a config waives a finding
(attestral/inline_suppress.py).

The contract: a `attestral:ignore ATL-xxx` marker in the file a finding came
from waives that finding in place, keeps it in the evidence chain (waived, not
deleted), and is fail-safe when it matches nothing. Works behind any comment
syntax because the marker is matched as a substring.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from attestral.cli import main
from attestral.inline_suppress import apply_inline_suppressions, markers_in
from attestral.model import Finding, Severity

# A fetch tool triggers ATL-107 (outbound network); the marker on its line
# should waive exactly that finding.
JSONC_WITH_MARKER = """{
  "mcpServers": {
    // web fetch
    "web": {"command": "uvx", "args": ["mcp-server-fetch"]},  // attestral:ignore ATL-107 reason: internal-only
    "shell": {"command": "bash", "args": ["-c", "mcp-shell-server"]}
  }
}
"""


def _finding(rule_id: str, source: str, component: str = "mcp_server.web") -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=Severity.HIGH, component_id=component,
        description="d", recommendation="r", source=source,
    )


# --- marker parsing ------------------------------------------------------------

def test_markers_parsed_with_reason():
    assert markers_in("// attestral:ignore ATL-107 reason: internal-only") == {
        "ATL-107": "internal-only"
    }


def test_bare_marker_has_empty_reason():
    assert markers_in("# attestral:ignore ATL-103") == {"ATL-103": ""}


def test_block_comment_reason_does_not_swallow_closer():
    assert markers_in("/* attestral:ignore ATL-107 reason: ok */")["ATL-107"] == "ok"


def test_rule_id_is_case_normalized():
    assert "ATL-107" in markers_in("// attestral:ignore atl-107")


# --- applying suppressions -----------------------------------------------------

def test_matching_marker_waives_finding_in_place(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(JSONC_WITH_MARKER)
    findings = [_finding("ATL-107", str(cfg))]
    notes = apply_inline_suppressions(findings)
    assert findings[0].waived is True
    assert findings[0].waiver_reason == "internal-only"
    assert findings[0].waived_by == "inline: .mcp.json"
    assert notes and "ATL-107" in notes[0]


def test_finding_stays_in_list_when_waived(tmp_path: Path):
    # Waived, not deleted: the finding is still present for the evidence chain.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(JSONC_WITH_MARKER)
    findings = [_finding("ATL-107", str(cfg))]
    apply_inline_suppressions(findings)
    assert len(findings) == 1


def test_marker_for_other_rule_does_not_match(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(JSONC_WITH_MARKER)
    findings = [_finding("ATL-103", str(cfg))]   # marker names ATL-107, not ATL-103
    apply_inline_suppressions(findings)
    assert findings[0].waived is False


def test_missing_source_file_is_a_noop():
    findings = [_finding("ATL-202", "system model", component="model")]
    notes = apply_inline_suppressions(findings)
    assert notes == []
    assert findings[0].waived is False


def test_already_waived_finding_is_left_alone(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(JSONC_WITH_MARKER)
    f = _finding("ATL-107", str(cfg))
    f.waived = True
    f.waiver_reason = "from waiver file"
    apply_inline_suppressions([f])
    assert f.waiver_reason == "from waiver file"   # inline pass did not overwrite


# --- CLI integration -----------------------------------------------------------

def test_scan_suppresses_inline_and_keeps_it_in_the_chain(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(JSONC_WITH_MARKER)
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    # The finding is reported as waived (kept), not silently dropped.
    assert "waived" in result.output.lower()
    assert "ATL-107" in result.output
