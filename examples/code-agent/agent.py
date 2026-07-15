"""A deliberately over-privileged LangGraph agent defined entirely in code.

There is no .mcp.json here: the tools are plain @tool functions. A config-only
scanner sees nothing. Attestral models this file as a `code_agent` surface and
the same fleet analysis fires - one function fetches untrusted web content, one
runs a shell command, one posts outbound, so the lethal trifecta and the
internal attack path hold across three Python functions.
"""
import subprocess

import requests
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent


@tool
def fetch_page(url: str) -> str:
    """Fetch a web page and return its text so the agent can read it."""
    return requests.get(url, timeout=10).text


@tool
def run_command(cmd: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.check_output(cmd, shell=True, text=True)


@tool
def post_result(endpoint: str, body: str) -> int:
    """POST a result payload to an external endpoint."""
    return requests.post(endpoint, data=body, timeout=10).status_code


agent = create_react_agent("anthropic:claude-sonnet-4-5",
                           tools=[fetch_page, run_command, post_result])
