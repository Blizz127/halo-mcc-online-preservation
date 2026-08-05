"""Minimal parser for Valve's text KeyValues format (.vdf, .acf).

Handles the subset actually emitted by Steam: quoted string tokens, nested
`{ }` blocks, and `//` line comments. No macro/conditional support (Steam
does not use it in the files this project reads: appmanifest_*.acf,
config.vdf, localconfig.vdf, toolmanifest.vdf, compatibilitytool.vdf).

Read-only tool: this module only parses text already on disk. It never
writes back to a Steam-owned file.
"""

from __future__ import annotations

from pathlib import Path

_WHITESPACE = " \t\r\n"


class VdfParseError(ValueError):
    pass


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in _WHITESPACE:
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c in "{}":
            tokens.append(c)
            i += 1
            continue
        if c == '"':
            j = i + 1
            buf: list[str] = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if j >= n:
                raise VdfParseError(f"unterminated quoted string starting at offset {i}")
            tokens.append("".join(buf))
            i = j + 1
            continue
        # Unquoted bareword token (rare in Steam-emitted files, but tolerated).
        j = i
        while j < n and text[j] not in _WHITESPACE and text[j] not in "{}":
            j += 1
        tokens.append(text[i:j])
        i = j
    return tokens


def parse(text: str) -> dict:
    """Parse KeyValues text into a nested dict of str -> (str | dict).

    Duplicate keys at the same level are folded into a list, preserving
    every value rather than silently dropping earlier ones.
    """
    tokens = _tokenize(text)
    pos = 0

    def parse_block() -> dict:
        nonlocal pos
        result: dict = {}
        while pos < len(tokens):
            tok = tokens[pos]
            if tok == "}":
                pos += 1
                return result
            key = tok
            pos += 1
            if pos >= len(tokens):
                raise VdfParseError(f"key {key!r} has no value at end of input")
            nxt = tokens[pos]
            if nxt == "{":
                pos += 1
                value = parse_block()
            elif nxt == "}":
                raise VdfParseError(f"key {key!r} followed by unexpected '}}'")
            else:
                value = nxt
                pos += 1
            if key in result:
                existing = result[key]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    result[key] = [existing, value]
            else:
                result[key] = value
        return result

    root = parse_block()
    if pos != len(tokens):
        raise VdfParseError(f"trailing tokens after top-level parse: {tokens[pos:pos + 5]!r}")
    return root


def parse_file(path: Path) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse(text)


def get_path(node: dict, *keys: str):
    """Walk a chain of keys through nested dicts; return None if any step misses."""
    current = node
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current
