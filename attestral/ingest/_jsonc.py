"""Tolerant JSON: parse configs that carry // and /* */ comments.

Real MCP client configs are JSONC in practice - VS Code, Cursor, and Claude
Desktop all read `.mcp.json`/settings with comments - so a strict `json.loads`
silently drops a whole file the moment a developer annotates it. It also blocks
inline suppression (`// attestral:ignore ATL-xxx`), which has to survive the
parse. This strips comments in a string-aware way (the `//` in a URL inside a
string literal is preserved) and changes nothing else: no trailing-comma or
other JSON5 leniency, so a genuinely malformed config still fails loudly.
"""
from __future__ import annotations

import json
from typing import Any


def strip_jsonc(text: str) -> str:
    """Return `text` with // line and /* block */ comments removed, preserving
    any comment-like sequence inside a JSON string literal."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:      # escape: keep the next char verbatim
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2                           # consume the closing */
            continue
        out.append(c)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    """`json.loads` after stripping JSONC comments."""
    return json.loads(strip_jsonc(text))
