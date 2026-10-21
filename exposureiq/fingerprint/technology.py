"""Pure technology hints from headers and an HTML generator meta tag (Saif).

These are disclosed product names, not proof of an installed version or a bug.
No requests are made, and the supplied response is never changed.
"""

import re
from html.parser import HTMLParser

from exposureiq.fingerprint.contract import MAX_BODY_BYTES

MAX_HINT_CHARS = 4096
# Anchored, bounded patterns: no nested repetition or searches over the body.
_PRODUCT = re.compile(r"[a-z][a-z0-9._+-]{0,127}(?![a-z0-9._+-])", re.IGNORECASE)
_VERSION = re.compile(r"[0-9][a-z0-9._+-]{0,127}(?![a-z0-9._+-])", re.IGNORECASE)
_RULE_BY_SOURCE = {
    "Server header": "tech.server_version_disclosed",
    "X-Powered-By header": "tech.powered_by_disclosed",
    "HTML generator meta tag": "tech.generator_version_disclosed",
}


def _product(value: str, source: str) -> dict | None:
    """Read the leading product and an optional numeric version, ignoring comments."""
    value = value[:MAX_HINT_CHARS].strip()
    match = _PRODUCT.match(value)
    if match is None:
        return None
    rest = value[match.end():]
    # A version follows either a slash or whitespace, never a parenthesized OS hint.
    version = ""
    if rest.startswith(("/", " ", "\t", "\r", "\n")):
        rest = rest.lstrip()
        if rest.startswith("/"):
            rest = rest[1:].lstrip()
        version_match = _VERSION.match(rest)
        if version_match is not None:
            version = version_match.group()
    return {"name": match.group().lower(), "version": version, "source": source}


class _GeneratorParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.generators = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "meta":
            return
        attributes = dict(attrs)
        name = attributes.get("name") or ""
        content = attributes.get("content") or ""
        if name.strip().lower() == "generator" and content.strip():
            self.generators.append(content)


def detect_technology(response: dict) -> list[dict]:
    """Return {name, version, source} hints; an unknown version is the string ""."""
    if not isinstance(response, dict):
        raise ValueError("response must be a dict")
    headers = response.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("response['headers'] must be a dict")
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
        raise ValueError("response headers must have string names and values")
    body = response.get("body", "")
    if not isinstance(body, str):
        raise ValueError("response['body'] must be a string")

    hints = []
    lowered = {name.lower(): value for name, value in headers.items()}
    for header, source in (("server", "Server header"), ("x-powered-by", "X-Powered-By header")):
        if lowered.get(header):
            hints.append((lowered[header], source))

    # Slice characters before encoding, so even a huge supplied body uses bounded memory.
    first_page = body[:MAX_BODY_BYTES].encode("utf-8")[:MAX_BODY_BYTES].decode("utf-8", errors="ignore")
    parser = _GeneratorParser()
    parser.feed(first_page)
    hints.extend((value, "HTML generator meta tag") for value in parser.generators)

    technologies, seen = [], set()
    for value, source in hints:
        technology = _product(value, source)
        if technology is None:
            continue
        identity = (technology["name"], technology["version"], source)
        if identity not in seen:
            seen.add(identity)
            technologies.append(technology)
    return technologies


def technology_findings(technologies: list) -> list[dict]:
    """Only an actually disclosed version produces a raw finding (rule + detail)."""
    if not isinstance(technologies, list):
        raise ValueError("technologies must be a list")
    findings, seen = [], set()
    for technology in technologies:
        if not isinstance(technology, dict):
            raise ValueError("each technology must be a dict")
        for key in ("name", "version", "source"):
            if not isinstance(technology.get(key), str):
                raise ValueError(f"technology['{key}'] must be a string")
        name, version, source = (technology[key].strip() for key in ("name", "version", "source"))
        if not name or not source:
            raise ValueError("technology name and source must not be empty")
        rule = _RULE_BY_SOURCE.get(source)
        identity = (rule, name, version)
        if version and rule and identity not in seen:
            seen.add(identity)
            findings.append({
                "rule": rule,
                "detail": f"{name} version {version} is disclosed in the {source}",
            })
    return findings
