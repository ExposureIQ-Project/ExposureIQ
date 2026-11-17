"""Lenient JSON decoding with a strict, unchanged structured-output shape.

Headline, next_steps and notes are {text, refs} claims. Priorities share refs
for their action and why. Ranks are structure; numbers in prose must use
code-filled placeholders. Unknown fields and oversized responses are rejected.
"""

from __future__ import annotations

import ast
import json

MAX_OUTPUT_CHARS = 24000
MAX_PRIORITIES = 16
MAX_CLAIMS = 20


class SchemaError(ValueError):
    pass


def _json_fragment(raw: str) -> tuple[str, bool]:
    """Ignore fences/wrappers; repair delimiters, never unfinished claim text."""
    start = raw.find("{")
    if start < 0:
        raise SchemaError("AI output was not valid JSON.")
    raw = raw[start:]
    stack, quote, escaped, result = [], "", False, []
    for position, char in enumerate(raw):
        if quote:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in ('"', "'"):
            quote = char
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
            if len(stack) > 32:
                raise SchemaError("AI JSON nesting exceeded the safe limit.")
        elif char in "}]":
            if not stack or stack.pop() != char:
                raise SchemaError("AI JSON had mismatched delimiters.")
            # Remove trailing commas only outside a quoted string.
            while result and result[-1].isspace():
                result.pop()
            if result and result[-1] == ",":
                result.pop()
        result.append(char)
        if not stack:
            return "".join(result), False
    if quote:
        raise SchemaError("AI JSON ended inside unfinished claim text; no text was invented.")
    value = "".join(result).rstrip()
    if value.endswith(","):
        value = value[:-1].rstrip()
    if value.endswith(":") or not stack:
        raise SchemaError("AI JSON ended inside an unfinished value.")
    return value + "".join(reversed(stack)), True


def decode_json(raw: str) -> dict:
    if len(raw) > MAX_OUTPUT_CHARS:
        raise SchemaError("AI output exceeded the size limit.")
    fragment, truncated = _json_fragment(raw)
    try:
        value = json.loads(fragment)
    except (ValueError, RecursionError):
        try:
            # literal_eval accepts only literals, never calls or executable code.
            value = ast.literal_eval(fragment)
        except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
            raise SchemaError("AI output was not usable JSON after safe delimiter repair.") from None
    if truncated and isinstance(value, dict) and "headline" in value:
        # Restore only empty structural sections. Missing words/refs are errors.
        value = {**value}
        for key in ("priorities", "notes", "next_steps"):
            value.setdefault(key, [])
    return value


def _refs(value):
    if (not isinstance(value, list) or not 1 <= len(value) <= 8
            or any(not isinstance(v, str) or not v or len(v) > 320 for v in value)
            or len(set(value)) != len(value)):
        raise SchemaError("Each claim needs a short, nonempty list of unique references.")


def _sentence(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise SchemaError("Claim text must be nonempty and at most 1000 characters.")


def _claim(value):
    if not isinstance(value, dict) or set(value) != {"text", "refs"}:
        raise SchemaError("Claims must contain only text and refs.")
    _sentence(value["text"])
    _refs(value["refs"])


def parse_output(raw: str | dict) -> dict:
    if isinstance(raw, str):
        raw = decode_json(raw)
    if not isinstance(raw, dict) or set(raw) != {"headline", "priorities", "next_steps", "notes"}:
        raise SchemaError("AI output must contain headline, priorities, next_steps and notes only.")
    _claim(raw["headline"])
    priorities = raw["priorities"]
    if not isinstance(priorities, list) or len(priorities) > MAX_PRIORITIES:
        raise SchemaError("AI output has too many priorities.")
    for rank, priority in enumerate(priorities, 1):
        if not isinstance(priority, dict) or set(priority) != {"rank", "action", "why", "refs"}:
            raise SchemaError("Each priority needs rank, action, why and refs only.")
        if isinstance(priority["rank"], bool) or not isinstance(priority["rank"], int) or priority["rank"] != rank:
            raise SchemaError("Priority ranks must be consecutive, starting at one.")
        _sentence(priority["action"])
        _sentence(priority["why"])
        _refs(priority["refs"])
    for key in ("next_steps", "notes"):
        if not isinstance(raw[key], list) or len(raw[key]) > MAX_CLAIMS:
            raise SchemaError("AI output has too many claims.")
        for claim in raw[key]:
            _claim(claim)
    return raw
