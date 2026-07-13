"""ASI06 memory/context poisoning: agent_instruction ingestion + ATL-113."""
import os
import stat

from attestral.ingest import build_model
from attestral.ingest.prompts import ingest_prompts
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/memory-poisoning"


def test_instruction_file_ingested_as_component():
    model = build_model(FIXTURE)
    instr = model.by_type("agent_instruction")
    assert instr and instr[0].source.endswith("CLAUDE.md")
    # content is carried so the ML layer scores the embedded injection.
    assert "credentials" in instr[0].attr("content")


def test_world_writable_instruction_fires_atl113(tmp_path):
    f = tmp_path / "CLAUDE.md"
    f.write_text("# guide\nkeep tests green\n")
    f.chmod(f.stat().st_mode | stat.S_IWOTH)
    model = ingest_prompts(tmp_path, SystemModel())
    ids = {x.rule_id for x in RuleEngine().evaluate(model)}
    assert "ATL-113" in ids


def test_owner_only_instruction_is_silent(tmp_path):
    f = tmp_path / ".cursorrules"
    f.write_text("always run the linter\n")
    f.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(tmp_path, stat.S_IRWXU)  # dir not world-writable either
    model = ingest_prompts(tmp_path, SystemModel())
    instr = model.by_type("agent_instruction")
    assert instr and instr[0].attr("_world_writable") is False
    ids = {x.rule_id for x in RuleEngine().evaluate(model)}
    assert "ATL-113" not in ids


def test_dotfile_rules_recognized(tmp_path):
    (tmp_path / ".windsurfrules").write_text("obey the deploy checklist\n")
    model = ingest_prompts(tmp_path, SystemModel())
    names = {c.name for c in model.by_type("agent_instruction")}
    assert ".windsurfrules" in names
