"""Data-shape checks for Stage 2 (the "contract" shared by all checks).

Each validator returns None when the data is fine and raises ValueError with a
clear message when it is not. Nothing here touches the network.
"""

import ipaddress
import re

MAX_BODY_BYTES = 100 * 1024  # response bodies are cut to 100 KB

RULE_RE = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$")
FINDING_ID_RE = re.compile(r"^F-\d{4,}$")

# The start of a rule ID decides the "check" name of the final finding.
CHECK_BY_GROUP = {
    "headers": "security_headers",
    "tech": "technology",
    "https": "https",
    "ports": "risky_services",
}

SEVERITIES = ("low", "medium", "high")

_RESPONSE_KEYS = {"host", "url", "scheme", "status", "headers", "body"}
_RAW_REQUIRED = {"rule", "detail"}
_RAW_OPTIONAL = {"ip", "port"}
_FINAL_REQUIRED = {"id", "rule", "check", "severity", "title", "detail", "recommendation"}
_FINAL_OPTIONAL = {"ip", "port"}


def _require_dict(value, what):
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be a dict, got {type(value).__name__}")


def _check_keys(data, required, optional, what):
    missing = required - data.keys()
    if missing:
        raise ValueError(f"{what} is missing key(s): {', '.join(sorted(missing))}")
    unknown = data.keys() - required - optional
    if unknown:
        raise ValueError(f"{what} has unexpected key(s): {', '.join(sorted(unknown))}")


def _non_empty_str(data, key, what):
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what}: '{key}' must be a non-empty string, got {value!r}")


def _check_rule(rule, what):
    if not isinstance(rule, str) or not RULE_RE.match(rule):
        raise ValueError(
            f"{what}: 'rule' must look like 'group.name' in lowercase, got {rule!r}"
        )


def _check_ip_port(data, what):
    if "ip" in data:
        ip = data["ip"]
        try:
            if not isinstance(ip, str):
                raise ValueError
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"{what}: 'ip' is not a valid IP address: {ip!r}") from None
    if "port" in data:
        port = data["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"{what}: 'port' must be an int from 1 to 65535, got {port!r}")


def validate_response(response: dict) -> None:
    """Keys: host, url, scheme ("http"/"https"), status (int), headers (dict,
    lowercase keys, string values), body (str, at most 100 KB, may be empty)."""
    what = "response"
    _require_dict(response, what)
    _check_keys(response, _RESPONSE_KEYS, set(), what)

    _non_empty_str(response, "host", what)
    _non_empty_str(response, "url", what)

    if response["scheme"] not in ("http", "https"):
        raise ValueError(f"{what}: 'scheme' must be 'http' or 'https', got {response['scheme']!r}")

    status = response["status"]
    if isinstance(status, bool) or not isinstance(status, int):
        raise ValueError(f"{what}: 'status' must be an int, got {status!r}")

    headers = response["headers"]
    if not isinstance(headers, dict):
        raise ValueError(f"{what}: 'headers' must be a dict, got {type(headers).__name__}")
    for name, value in headers.items():
        if not isinstance(name, str) or name != name.lower():
            raise ValueError(f"{what}: header name must be a lowercase string, got {name!r}")
        if not isinstance(value, str):
            raise ValueError(f"{what}: header '{name}' must have a string value, got {value!r}")

    body = response["body"]
    if not isinstance(body, str):
        raise ValueError(f"{what}: 'body' must be a string, got {type(body).__name__}")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError(f"{what}: 'body' is longer than {MAX_BODY_BYTES} bytes")


def validate_raw_finding(finding: dict) -> None:
    """Required: rule (must look like "group.name", lowercase), detail (non-empty str).
    Optional: ip (valid IP string), port (int 1 to 65535). No other keys."""
    what = "raw finding"
    _require_dict(finding, what)
    _check_keys(finding, _RAW_REQUIRED, _RAW_OPTIONAL, what)
    _check_rule(finding["rule"], what)
    _non_empty_str(finding, "detail", what)
    _check_ip_port(finding, what)


def validate_finding(finding: dict) -> None:
    """Final finding: id (F-0001 style), rule, check, severity (low/medium/high),
    title, detail, recommendation (non-empty strings). Optional: ip, port.
    No other keys."""
    what = "finding"
    _require_dict(finding, what)
    _check_keys(finding, _FINAL_REQUIRED, _FINAL_OPTIONAL, what)

    fid = finding["id"]
    if not isinstance(fid, str) or not FINDING_ID_RE.match(fid):
        raise ValueError(f"{what}: 'id' must look like 'F-0001', got {fid!r}")

    _check_rule(finding["rule"], what)

    for key in ("check", "title", "detail", "recommendation"):
        _non_empty_str(finding, key, what)

    if finding["severity"] not in SEVERITIES:
        raise ValueError(
            f"{what}: 'severity' must be one of {', '.join(SEVERITIES)}, got {finding['severity']!r}"
        )

    group = finding["rule"].split(".", 1)[0]
    expected = CHECK_BY_GROUP.get(group)
    if expected is None:
        raise ValueError(f"{what}: unknown rule group {group!r} in rule {finding['rule']!r}")
    if finding["check"] != expected:
        raise ValueError(
            f"{what}: 'check' for rule {finding['rule']!r} must be {expected!r}, got {finding['check']!r}"
        )

    _check_ip_port(finding, what)
