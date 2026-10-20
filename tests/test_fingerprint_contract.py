"""Tests for the contract validators and for every fixture file.

Pure tests: no network, no teammate modules needed.
"""

import copy
import json
import re
from pathlib import Path

import pytest

from exposureiq.fingerprint.contract import (
    validate_finding,
    validate_raw_finding,
    validate_response,
)

FIXTURES = Path(__file__).parent / "fixtures"
RESPONSE_NAMES = ["well_configured", "bare_minimum", "old_nginx_php", "http_only"]
CERT_NAMES = ["valid", "expired", "expiring_soon", "self_signed", "hostname_mismatch"]
CERT_KEYS = {"host", "subject", "issuer", "san", "not_before", "not_after", "verified"}


def load(kind, name):
    return json.loads((FIXTURES / kind / f"{name}.json").read_text(encoding="utf-8"))


GOOD_RESPONSE = {
    "host": "api.example.com",
    "url": "https://api.example.com/",
    "scheme": "https",
    "status": 200,
    "headers": {"server": "nginx", "content-type": "text/html"},
    "body": "<html></html>",
}
GOOD_RAW = {"rule": "headers.missing_csp", "detail": "No CSP on https://api.example.com/"}
GOOD_FINAL = {
    "id": "F-0001",
    "rule": "headers.missing_csp",
    "check": "security_headers",
    "severity": "medium",
    "title": "Missing Content-Security-Policy header",
    "detail": "No CSP on https://api.example.com/",
    "recommendation": "Add a Content-Security-Policy header.",
}


def changed(base, **changes):
    data = copy.deepcopy(base)
    data.update(changes)
    return data


def without(base, key):
    data = copy.deepcopy(base)
    del data[key]
    return data


# ---------------------------------------------------------------- fixtures

@pytest.mark.parametrize("name", RESPONSE_NAMES)
def test_every_response_fixture_is_valid(name):
    validate_response(load("responses", name))


@pytest.mark.parametrize("name", CERT_NAMES)
def test_every_cert_fixture_has_the_agreed_keys(name):
    info = load("certs", name)
    assert set(info) == CERT_KEYS
    assert isinstance(info["san"], list) and isinstance(info["verified"], bool)


def test_there_are_exactly_9_fixture_files():
    assert len(list(FIXTURES.glob("responses/*.json"))) == 4
    assert len(list(FIXTURES.glob("certs/*.json"))) == 5


def test_fixtures_use_only_example_data():
    for path in FIXTURES.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        for host in re.findall(r"[a-z0-9.-]+\.(?:com|net|org|io|eg|co|info|biz)\b", text):
            assert host.endswith("example.com"), f"{path.name}: real-looking host {host}"
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
            assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), f"{path.name}: {ip}"


def test_http_only_fixture_really_is_http():
    resp = load("responses", "http_only")
    assert resp["scheme"] == "http" and resp["url"].startswith("http://")


# ---------------------------------------------------------------- validate_response

def test_response_valid_empty_body_is_ok():
    validate_response(changed(GOOD_RESPONSE, body=""))


def test_response_valid_body_exactly_100kb_is_ok():
    validate_response(changed(GOOD_RESPONSE, body="a" * 102400))


@pytest.mark.parametrize("key", ["host", "url", "scheme", "status", "headers", "body"])
def test_response_missing_key(key):
    with pytest.raises(ValueError, match=key):
        validate_response(without(GOOD_RESPONSE, key))


@pytest.mark.parametrize(
    "changes",
    [
        {"scheme": "ftp"},
        {"scheme": "HTTPS"},
        {"status": "200"},
        {"status": True},
        {"host": ""},
        {"headers": ["server"]},
        {"headers": {"Server": "nginx"}},
        {"headers": {"server": 123}},
        {"body": None},
        {"body": "a" * 102401},
        {"extra": 1},
    ],
)
def test_response_bad_values(changes):
    with pytest.raises(ValueError):
        validate_response(changed(GOOD_RESPONSE, **changes))


@pytest.mark.parametrize("bad", [None, "text", 5, [GOOD_RESPONSE]])
def test_response_not_a_dict(bad):
    with pytest.raises(ValueError, match="dict"):
        validate_response(bad)


# ---------------------------------------------------------------- validate_raw_finding

def test_raw_finding_minimal_ok():
    validate_raw_finding(GOOD_RAW)


def test_raw_finding_with_ip_and_port_ok():
    validate_raw_finding(changed(GOOD_RAW, rule="ports.ftp_exposed", ip="203.0.113.10", port=21))


def test_raw_finding_ipv6_documentation_address_ok():
    validate_raw_finding(changed(GOOD_RAW, ip="2001:db8::1"))


@pytest.mark.parametrize("key", ["rule", "detail"])
def test_raw_finding_missing_required(key):
    with pytest.raises(ValueError, match=key):
        validate_raw_finding(without(GOOD_RAW, key))


@pytest.mark.parametrize(
    "changes",
    [
        {"rule": "Headers.Missing_CSP"},
        {"rule": "headers"},
        {"rule": "headers.missing-csp"},
        {"rule": ".missing_csp"},
        {"rule": 5},
        {"detail": ""},
        {"detail": "   "},
        {"detail": 5},
        {"ip": "999.1.1.1"},
        {"ip": "not an ip"},
        {"ip": 12345},
        {"port": 0},
        {"port": 65536},
        {"port": "21"},
        {"port": True},
        {"severity": "high"},
        {"title": "no extra keys allowed"},
    ],
)
def test_raw_finding_bad_values(changes):
    with pytest.raises(ValueError):
        validate_raw_finding(changed(GOOD_RAW, **changes))


def test_raw_finding_port_limits_ok():
    validate_raw_finding(changed(GOOD_RAW, port=1))
    validate_raw_finding(changed(GOOD_RAW, port=65535))


@pytest.mark.parametrize("bad", [None, "x", [GOOD_RAW]])
def test_raw_finding_not_a_dict(bad):
    with pytest.raises(ValueError, match="dict"):
        validate_raw_finding(bad)


# ---------------------------------------------------------------- validate_finding

def test_final_finding_ok():
    validate_finding(GOOD_FINAL)


def test_final_finding_with_ip_and_port_ok():
    validate_finding(
        changed(GOOD_FINAL, id="F-0012", rule="ports.database_exposed", check="risky_services",
                severity="high", ip="203.0.113.10", port=3306)
    )


@pytest.mark.parametrize("fid", ["F-0001", "F-0100", "F-12345"])
def test_final_finding_id_styles_ok(fid):
    validate_finding(changed(GOOD_FINAL, id=fid))


@pytest.mark.parametrize("key", sorted(GOOD_FINAL))
def test_final_finding_missing_key(key):
    with pytest.raises(ValueError, match=key):
        validate_finding(without(GOOD_FINAL, key))


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "F-1"},
        {"id": "f-0001"},
        {"id": "0001"},
        {"severity": "critical"},
        {"severity": "High"},
        {"title": ""},
        {"recommendation": ""},
        {"detail": None},
        {"check": "https"},          # does not match the rule group "headers"
        {"rule": "other.thing"},     # unknown group
        {"port": 99999},
        {"ip": "300.0.0.1"},
        {"unknown_key": "x"},
    ],
)
def test_final_finding_bad_values(changes):
    with pytest.raises(ValueError):
        validate_finding(changed(GOOD_FINAL, **changes))


def test_error_messages_name_the_problem():
    with pytest.raises(ValueError, match="severity"):
        validate_finding(changed(GOOD_FINAL, severity="critical"))
    with pytest.raises(ValueError, match="unexpected key"):
        validate_raw_finding(changed(GOOD_RAW, severity="low"))
