"""Tests for check_security_headers. Pure data in, data out: no network."""

import pytest

from exposureiq.fingerprint.headers import check_security_headers

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
}


def make_response(headers=None, scheme="https"):
    return {
        "host": "example.com",
        "url": f"{scheme}://example.com/",
        "scheme": scheme,
        "status": 200,
        "headers": GOOD_HEADERS if headers is None else headers,
        "body": "",
    }


def rules(response):
    return [f["rule"] for f in check_security_headers(response)]


def without(name):
    return {k: v for k, v in GOOD_HEADERS.items() if k != name}


def test_fully_secure_page_has_no_findings():
    assert check_security_headers(make_response()) == []


def test_response_none_returns_empty_list():
    assert check_security_headers(None) == []


def test_example_from_brief():
    response = make_response({"x-content-type-options": "nosniff"})
    findings = check_security_headers(response)
    assert [f["rule"] for f in findings] == [
        "headers.missing_hsts",
        "headers.missing_csp",
        "headers.missing_clickjacking_protection",
        "headers.missing_referrer_policy",
        "headers.missing_permissions_policy",
    ]
    assert findings[0]["detail"] == (
        "No Strict-Transport-Security header on https://example.com/")
    assert findings[1]["detail"] == (
        "No Content-Security-Policy header on https://example.com/")
    assert all(set(f) == {"rule", "detail"} for f in findings)


def test_missing_hsts_fires_on_https_only():
    assert "headers.missing_hsts" in rules(make_response(without("strict-transport-security")))
    http_page = make_response(without("strict-transport-security"), scheme="http")
    assert "headers.missing_hsts" not in rules(http_page)


def test_http_page_skips_all_hsts_rules():
    http_page = make_response({"strict-transport-security": "max-age=10"}, scheme="http")
    found = rules(http_page)
    assert "headers.missing_hsts" not in found
    assert "headers.weak_hsts" not in found


@pytest.mark.parametrize("value", [
    "includeSubDomains",          # no max-age
    "max-age=abc",                # not a number
    "max-age=",                   # empty
    "max-age=-5",                 # not a valid number
    "max-age=100",                # too low
    "max-age=15552000000x",       # junk after the number
    "max-age=15551999",           # one second below the limit
])
def test_weak_hsts_values_fire(value):
    headers = {**GOOD_HEADERS, "strict-transport-security": value}
    assert "headers.weak_hsts" in rules(make_response(headers))


@pytest.mark.parametrize("value", [
    "max-age=15552000",
    "max-age=31536000; includeSubDomains; preload",
    "includeSubDomains; MAX-AGE=31536000",
    'max-age="31536000"',
])
def test_strong_hsts_values_do_not_fire(value):
    headers = {**GOOD_HEADERS, "strict-transport-security": value}
    found = rules(make_response(headers))
    assert "headers.weak_hsts" not in found
    assert "headers.missing_hsts" not in found


def test_missing_csp_fires_and_present_csp_does_not():
    assert "headers.missing_csp" in rules(make_response(without("content-security-policy")))
    assert "headers.missing_csp" not in rules(make_response())


@pytest.mark.parametrize("csp", [
    "script-src 'self' 'unsafe-inline'",
    "script-src 'self' 'UNSAFE-EVAL'",
    "script-src *",
    "default-src * ; frame-ancestors 'none'",           # default-src fallback
    "default-src 'unsafe-inline'; frame-ancestors 'none'",
    "img-src 'self'; script-src https://a.com 'unsafe-eval'; frame-ancestors 'none'",
])
def test_weak_csp_variants_fire(csp):
    headers = {**GOOD_HEADERS, "content-security-policy": csp}
    assert "headers.weak_csp" in rules(make_response(headers))


@pytest.mark.parametrize("csp", [
    "default-src 'self'; frame-ancestors 'none'",
    "script-src 'self' https://cdn.example.com; frame-ancestors 'none'",
    "script-src 'self'; default-src *; frame-ancestors 'none'",   # script-src wins
    "script-src https://*.example.com; frame-ancestors 'none'",  # not a bare *
    "style-src 'unsafe-inline'; frame-ancestors 'none'",         # only scripts count
])
def test_safe_csp_variants_do_not_fire_weak_csp(csp):
    headers = {**GOOD_HEADERS, "content-security-policy": csp}
    assert "headers.weak_csp" not in rules(make_response(headers))


def test_missing_csp_does_not_also_report_weak_csp():
    found = rules(make_response(without("content-security-policy")))
    assert "headers.weak_csp" not in found


@pytest.mark.parametrize("value, fires", [
    ("nosniff", False),
    ("NoSniff", False),
    (" NOSNIFF ", False),
    ("sniff", True),
    ("", True),
])
def test_x_content_type_options_value_and_case(value, fires):
    headers = {**GOOD_HEADERS, "x-content-type-options": value}
    assert ("headers.missing_x_content_type_options" in rules(make_response(headers))) is fires


def test_x_content_type_options_missing_fires():
    assert "headers.missing_x_content_type_options" in rules(
        make_response(without("x-content-type-options")))


def test_clickjacking_needs_both_protections_missing():
    no_csp_ancestors = {**GOOD_HEADERS, "content-security-policy": "default-src 'self'"}
    assert "headers.missing_clickjacking_protection" in rules(make_response(no_csp_ancestors))
    with_xfo = {**no_csp_ancestors, "x-frame-options": "DENY"}
    assert "headers.missing_clickjacking_protection" not in rules(make_response(with_xfo))
    assert "headers.missing_clickjacking_protection" not in rules(make_response())  # frame-ancestors
    no_csp_at_all = without("content-security-policy")
    assert "headers.missing_clickjacking_protection" in rules(make_response(no_csp_at_all))


def test_missing_referrer_policy():
    assert "headers.missing_referrer_policy" in rules(make_response(without("referrer-policy")))
    assert "headers.missing_referrer_policy" not in rules(make_response())


def test_missing_permissions_policy():
    assert "headers.missing_permissions_policy" in rules(make_response(without("permissions-policy")))
    assert "headers.missing_permissions_policy" not in rules(make_response())


def test_one_finding_per_rule_never_duplicates():
    found = rules(make_response({}))
    assert len(found) == len(set(found))


def test_header_names_in_any_case_are_understood():
    upper = {k.upper(): v for k, v in GOOD_HEADERS.items()}
    assert check_security_headers(make_response(upper)) == []
