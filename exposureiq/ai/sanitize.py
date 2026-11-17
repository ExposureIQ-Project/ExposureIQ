"""Treat saved scan text as untrusted data, never as instructions or markup."""

from __future__ import annotations

import json
import re
import unicodedata

HOSTILE = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|"
    r"(?:reveal|print|return)\s+(?:your\s+)?(?:system\s+prompt|api\s+key)|"
    r"report\s+no\s+issues|<\s*script|onerror\s*=|\[/?(?:bold|link)|"
    r"\[/?(?:system|assistant)\]|(?:system|assistant)\s*:", re.I,
)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
SECRET_KEYS = frozenset({"api_key", "key", "authorization", "token", "password"})


def text(value, limit: int = 160) -> str:
    """Bounded plain text; remove terminal controls and bidirectional overrides."""
    if not isinstance(value, str):
        return ""
    return CONTROL.sub(" ", unicodedata.normalize("NFKC", value)).strip()[:limit]


def label(value, limit: int = 80) -> str:
    """Normalized labels contain no banners, HTML, markup, or instructions."""
    clean = text(value, limit)
    if HOSTILE.search(clean):
        return "untrusted text omitted"
    return re.sub(r"[^\w .:+/()_-]", "", clean, flags=re.ASCII).strip()


def host_name(value) -> str:
    clean = text(value, 253).lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", clean):
        return "untrusted-host"
    return clean


def hostile_seen(value) -> bool:
    """Inspect without copying raw text into the digest, prompt or log."""
    if isinstance(value, str):
        return bool(HOSTILE.search(value) or CONTROL.search(value))
    if isinstance(value, dict):
        return any(hostile_seen(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(hostile_seen(item) for item in value)
    return False


def redact(value, secrets: tuple[str, ...] = ()):
    """Defence in depth for logs/caches. Never include credential fields."""
    if isinstance(value, dict):
        return {str(k): redact(v, secrets) for k, v in value.items()
                if str(k).lower() not in SECRET_KEYS}
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        clean = value
        for secret in secrets:
            if secret:
                for variant in {secret, json.dumps(secret, ensure_ascii=True)[1:-1],
                                json.dumps(secret, ensure_ascii=False)[1:-1]}:
                    clean = clean.replace(variant, "[redacted]")
        return CONTROL.sub(" ", clean)
    return value


def compact_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def estimated_tokens(value) -> float:
    return len(compact_json(value)) / 4
