"""CLI behaviour tests: terminal-first output, init, explain, quiet.

Uses click's CliRunner so nothing touches the developer's real filesystem -
file-writing cases run inside an isolated_filesystem() sandbox.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from attestral.cli import main

REPO = Path(__file__).resolve().parent.parent
VULN = str(REPO / "examples" / "vulnerable-agent")


# --- terminal-first output ---------------------------------------------------

def test_scan_writes_no_files_by_default():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["scan", VULN])
        assert result.exit_code == 0
        # No report artifacts littered into the working directory.
        assert not Path("attestral-report.md").exists()
        assert not Path("attestral-report.json").exists()
        assert list(Path(".").glob("attestral-report.*")) == []
        # Findings still print, and we say nothing was written.
        assert "findings" in result.output
        assert "no files written" in result.output


def test_scan_writes_files_with_output_flag():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["scan", VULN, "-o", "report"])
        assert result.exit_code == 0
        assert Path("report.md").exists()
        assert Path("report.json").exists()
        assert "wrote report.md" in result.output
        assert "wrote report.json" in result.output


def test_scan_format_json_writes_only_json():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["scan", VULN, "--format", "json"])
        assert result.exit_code == 0
        assert Path("attestral-report.json").exists()
        assert not Path("attestral-report.md").exists()


def test_scan_fail_on_gate_exits_nonzero():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["scan", VULN, "--fail-on", "high"])
        assert result.exit_code == 1
        assert "FAIL-CLOSED" in result.output


# --- --quiet -----------------------------------------------------------------

def test_quiet_suppresses_per_finding_lines():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["scan", VULN, "--quiet"])
        assert result.exit_code == 0
        # Summary line still present; per-finding detail and hints are gone.
        assert "findings" in result.output
        assert "run: attestral explain" not in result.output
        assert "fix:" not in result.output
        # Quiet also drops the "no files written" hint.
        assert "no files written" not in result.output


def test_quiet_clean_scan_is_silent(tmp_path):
    runner = CliRunner()
    empty = tmp_path / "empty"
    empty.mkdir()
    result = runner.invoke(main, ["scan", str(empty), "--quiet"])
    assert result.exit_code == 0
    assert result.output.strip() == ""


# --- explain -----------------------------------------------------------------

def test_explain_known_rule():
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "ATL-103"])
    assert result.exit_code == 0
    assert "Shell-capable MCP server configured" in result.output
    assert "critical" in result.output
    assert "Recommendation" in result.output
    assert "OWASP-ASI05:2026" in result.output


def test_explain_is_case_insensitive():
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "atl-103"])
    assert result.exit_code == 0
    assert "Shell-capable MCP server configured" in result.output


def test_explain_unknown_rule_is_helpful():
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "ATL-999"])
    assert result.exit_code == 1
    assert "Unknown rule id" in result.output
    # Points the user at the full list of ids.
    assert "Available ids" in result.output
    assert "ATL-103" in result.output


# --- init --------------------------------------------------------------------

def test_init_scaffolds_files():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        assert Path(".github/workflows/attestral.yml").exists()
        assert Path(".pre-commit-config.yaml").exists()
        assert Path("attestral-waivers.yaml").exists()
        assert "created" in result.output
        assert "Next steps" in result.output


def test_init_never_overwrites_existing_files():
    runner = CliRunner()
    with runner.isolated_filesystem():
        # Pre-seed one of the three targets with sentinel content.
        Path("attestral-waivers.yaml").write_text("SENTINEL - do not touch\n")
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        # The existing file is reported as skipped and left untouched.
        assert "skipped attestral-waivers.yaml" in result.output
        assert Path("attestral-waivers.yaml").read_text() == "SENTINEL - do not touch\n"
        # The other two are still created.
        assert Path(".github/workflows/attestral.yml").exists()
        assert Path(".pre-commit-config.yaml").exists()


def test_init_is_idempotent_second_run_skips_all():
    runner = CliRunner()
    with runner.isolated_filesystem():
        first = runner.invoke(main, ["init"])
        assert first.exit_code == 0
        second = runner.invoke(main, ["init"])
        assert second.exit_code == 0
        assert second.output.count("skipped") == 3
        assert "Nothing to do" in second.output
