"""M11: ingest agents defined in code, mapped to the same capability vocabulary
so the fleet rules and attack-path synthesis fire on code as on config."""
from attestral.ingest import build_model
from attestral.ingest.agent_code import ingest_agent_code
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/code-agent"


def _model(tmp_path, name: str, code: str) -> SystemModel:
    (tmp_path / name).write_text(code)
    return build_model(str(tmp_path))


def test_langgraph_tools_yield_capabilities():
    model = build_model(FIXTURE)
    agents = model.by_type("code_agent")
    assert len(agents) == 1
    a = agents[0]
    assert a.name == "agent"                       # picked up the Agent variable
    assert set(a.attr("_capabilities")) == {"network", "shell"}
    assert set(a.attr("_tool_names")) == {"fetch_page", "run_command", "post_result"}
    assert "langgraph" in a.attr("_framework")


def test_code_agent_drives_fleet_and_path_rules():
    model = build_model(FIXTURE)
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-203" in ids   # shell + network across the tools
    assert "ATL-207" in ids   # untrusted input can reach the shell tool
    from attestral.paths import all_attack_paths
    assert len(all_attack_paths(model)) == 1


def test_plain_script_is_not_an_agent(tmp_path):
    model = _model(tmp_path, "util.py",
                   "import subprocess\n"
                   "def helper():\n    return subprocess.check_output('ls', shell=True)\n")
    assert model.by_type("code_agent") == []   # no framework import: not an agent


def test_framework_import_without_tools_is_not_modeled(tmp_path):
    model = _model(tmp_path, "client.py",
                   "import anthropic\nc = anthropic.Anthropic()\n")
    assert model.by_type("code_agent") == []   # imports a framework but defines no tool


def test_anthropic_tool_dicts_classified_from_text(tmp_path):
    code = (
        "import anthropic\n"
        "TOOLS = [\n"
        "  {'name': 'run_shell', 'description': 'execute a bash command',\n"
        "   'input_schema': {'type': 'object'}},\n"
        "  {'name': 'fetch_url', 'description': 'download a web page',\n"
        "   'input_schema': {'type': 'object'}},\n"
        "]\n"
    )
    model = _model(tmp_path, "tools.py", code)
    agents = model.by_type("code_agent")
    assert len(agents) == 1
    caps = set(agents[0].attr("_capabilities"))
    assert "shell" in caps and "network" in caps


def test_function_tool_decorator_and_messaging_capability(tmp_path):
    code = (
        "from agents import function_tool\n"
        "import slack_sdk\n"
        "@function_tool\n"
        "def notify(text: str):\n"
        "    '''send a slack message'''\n"
        "    slack_sdk.WebClient().chat_postMessage(text=text)\n"
    )
    model = _model(tmp_path, "notify.py", code)
    agents = model.by_type("code_agent")
    assert len(agents) == 1
    assert "messaging" in agents[0].attr("_capabilities")
    assert "openai-agents" in agents[0].attr("_framework")


def test_syntax_error_file_is_skipped_not_fatal(tmp_path):
    (tmp_path / "broken.py").write_text("import anthropic\n@tool\ndef x(:\n")
    # must not raise; the unparseable file is simply skipped
    model = ingest_agent_code(str(tmp_path), SystemModel())
    assert model.by_type("code_agent") == []


def test_duplicate_agent_names_get_distinct_ids(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    body = ("from langchain_core.tools import tool\n"
            "@tool\ndef fetch(u: str):\n    '''fetch a url'''\n    import requests\n"
            "    return requests.get(u).text\n")
    (tmp_path / "a" / "agent.py").write_text(body)
    (tmp_path / "b" / "agent.py").write_text(body)
    model = build_model(str(tmp_path))
    ids = [c.id for c in model.by_type("code_agent")]
    assert len(ids) == 2 and len(set(ids)) == 2   # no id collision
