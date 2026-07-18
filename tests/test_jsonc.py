"""Tolerant JSON parsing for MCP configs (attestral/ingest/_jsonc.py).

Real MCP client configs carry comments; a strict json.loads drops the whole
file the moment one is added. The stripper must remove // and /* */ comments
without corrupting comment-like text inside string literals (URLs), and must
leave genuinely malformed JSON failing loudly.
"""
from __future__ import annotations

import json

import pytest

from attestral.ingest import _jsonc


def test_line_comment_stripped():
    assert _jsonc.loads('{\n  // a note\n  "a": 1\n}') == {"a": 1}


def test_trailing_line_comment_stripped():
    assert _jsonc.loads('{"a": 1}  // trailing') == {"a": 1}


def test_block_comment_stripped():
    assert _jsonc.loads('{"a": /* inline */ 1}') == {"a": 1}


def test_url_inside_string_is_preserved():
    # The // in a URL is inside a string literal and must survive.
    out = _jsonc.loads('{"url": "https://example.com/api"}')
    assert out["url"] == "https://example.com/api"


def test_block_comment_marker_inside_string_preserved():
    out = _jsonc.loads('{"note": "a /* not a comment */ b"}')
    assert out["note"] == "a /* not a comment */ b"


def test_escaped_quote_in_string_does_not_end_it():
    out = _jsonc.loads(r'{"q": "she said \"// hi\""}')
    assert out["q"] == 'she said "// hi"'


def test_plain_json_unchanged():
    assert _jsonc.loads('{"a": [1, 2], "b": {"c": true}}') == {"a": [1, 2], "b": {"c": True}}


def test_malformed_json_still_raises():
    with pytest.raises(json.JSONDecodeError):
        _jsonc.loads('{"a": }')


def test_strip_leaves_string_bytes_intact():
    # strip_jsonc only removes comments; string content is byte-for-byte intact.
    src = '{"cmd": "a//b", "x": 1 /* c */}'
    stripped = _jsonc.strip_jsonc(src)
    assert '"a//b"' in stripped
    assert "/* c */" not in stripped
