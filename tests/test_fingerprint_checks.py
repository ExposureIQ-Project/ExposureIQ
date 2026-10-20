"""Check each Stage 2 check against the shared fixtures.

Teammate modules are loaded with pytest.importorskip, so a test is skipped until
the module is merged and then runs by itself. No network is used anywhere here.

ASSUMPTIONS to confirm with the owners (change only the small helpers below):
  * detect_technology(response) -> list of {"name", "version", "source"}
  * technology_findings(technologies) -> raw findings
  * analyze_certificate(info, now=...) -> raw findings, info keys as in the cert fixtures
  * check_risky_ports(ips) where ips = [{"ip", "open_ports": [{"port", "protocol", "service"}]}]
"""

import copy
import json
from pathlib import Path

import pytest

from exposureiq.fingerprint.contract import validate_raw_finding

FIXTURES = Path(__file__).parent / "fixtures"
NOW = "2026-10-20T00:00:00Z"

MISSING_HEADER_RULES = {
    "headers.missing_hsts",
    "headers.missing_csp",
    "headers.missing_x_content_type_options",
    "headers.missing_clickjacking_protection",
    "headers.missing_referrer_policy",
    "headers.missing_permissions_policy",
}


def load(kind, name):
    return json.loads((FIXTURES / kind / f"{name}.json").read_text(encoding="utf-8"))


def rules(findings):
    return {f["rule"] for f in findings}


def variant(base, set_headers=None, drop=(), **top):
    data = copy.deepcopy(base)
    data["headers"].update(set_headers or {})
    for name in drop:
        data["headers"].pop(name, None)
    data.update(top)
    return data


# ---- small adapters: the only place that knows how teammates' functions are called

def headers_mod():
    return pytest.importorskip("exposureiq.fingerprint.headers")


def tech_mod():
    return pytest.importorskip("exposureiq.fingerprint.technology")


def https_mod():
    return pytest.importorskip("exposureiq.fingerprint.https_checks")


def ports_mod():
    return pytest.importorskip("exposureiq.fingerprint.risky_ports")


def run_headers(response):
    return headers_mod().check_security_headers(response)


def run_cert(info, now=NOW):
    return https_mod().analyze_certificate(info, now=now)


def run_ports(port, service="unknown"):
    ips = [{"ip": "203.0.113.10", "open_ports": [{"port": port, "protocol": "tcp", "service": service}]}]
    return ports_mod().check_risky_ports(ips)


# ================================================================ security headers

def test_headers_well_configured_gives_nothing():
    assert run_headers(load("responses", "well_configured")) == []


def test_headers_bare_minimum_gives_exactly_the_six_missing_rules():
    found = run_headers(load("responses", "bare_minimum"))
    assert rules(found) == MISSING_HEADER_RULES
    assert len(found) == 6, "each rule should fire once"


def test_headers_bare_minimum_has_no_weak_rules():
    found = rules(run_headers(load("responses", "bare_minimum")))
    assert "headers.weak_hsts" not in found and "headers.weak_csp" not in found


def test_headers_http_only_skips_hsts_but_keeps_the_rest():
    found = rules(run_headers(load("responses", "http_only")))
    assert "headers.missing_hsts" not in found
    assert found == MISSING_HEADER_RULES - {"headers.missing_hsts"}


@pytest.mark.parametrize(
    "hsts, expected",
    [
        ("max-age=15552000", set()),                       # exactly 180 days: fine
        ("max-age=31536000; includeSubDomains", set()),
        ("max-age=15551999", {"headers.weak_hsts"}),       # one second short
        ("max-age=3600", {"headers.weak_hsts"}),
        ("includeSubDomains", {"headers.weak_hsts"}),      # no max-age at all
    ],
)
def test_headers_hsts_strength(hsts, expected):
    resp = variant(load("responses", "well_configured"), {"strict-transport-security": hsts})
    assert rules(run_headers(resp)) == expected


@pytest.mark.parametrize(
    "csp, expected",
    [
        ("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", {"headers.weak_csp"}),
        ("default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'", {"headers.weak_csp"}),
        ("default-src *; frame-ancestors 'none'", {"headers.weak_csp"}),
        ("script-src *; frame-ancestors 'none'", {"headers.weak_csp"}),
        # not weak: unsafe-inline only in styles, and a wildcard sub-domain is not a bare *
        ("default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'", set()),
        ("default-src 'self'; script-src 'self' *.example.com; frame-ancestors 'none'", set()),
    ],
)
def test_headers_csp_strength(csp, expected):
    resp = variant(load("responses", "well_configured"), {"content-security-policy": csp})
    assert rules(run_headers(resp)) == expected


def test_headers_x_content_type_options_must_be_nosniff():
    base = load("responses", "well_configured")
    bad = variant(base, {"x-content-type-options": "sniff-away"})
    assert rules(run_headers(bad)) == {"headers.missing_x_content_type_options"}


def test_headers_clickjacking_xfo_alone_is_enough():
    base = load("responses", "well_configured")
    resp = variant(base, {"content-security-policy": "default-src 'self'"})  # no frame-ancestors, XFO stays
    assert rules(run_headers(resp)) == set()


def test_headers_clickjacking_csp_frame_ancestors_alone_is_enough():
    resp = variant(load("responses", "well_configured"), drop=["x-frame-options"])
    assert rules(run_headers(resp)) == set()


def test_headers_clickjacking_fires_when_both_are_missing():
    resp = variant(
        load("responses", "well_configured"),
        {"content-security-policy": "default-src 'self'"},
        drop=["x-frame-options"],
    )
    assert rules(run_headers(resp)) == {"headers.missing_clickjacking_protection"}


def test_headers_each_findings_is_a_valid_raw_finding():
    for finding in run_headers(load("responses", "bare_minimum")):
        validate_raw_finding(finding)


def test_headers_do_not_change_their_input():
    resp = load("responses", "bare_minimum")
    before = copy.deepcopy(resp)
    run_headers(resp)
    assert resp == before


@pytest.mark.parametrize("bad", [None, "text", 42, ["headers"]])
def test_headers_bad_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        run_headers(bad)


# ================================================================ technology

def tech_pairs(technologies):
    return {(t["name"].lower(), t.get("version")) for t in technologies}


def test_technology_well_configured_gives_nothing():
    assert tech_mod().detect_technology(load("responses", "well_configured")) == []


def test_technology_old_nginx_php_finds_three():
    techs = tech_mod().detect_technology(load("responses", "old_nginx_php"))
    assert len(techs) == 3
    assert tech_pairs(techs) == {("nginx", "1.18.0"), ("php", "8.1.2"), ("wordpress", "6.4.2")}
    assert all(t.get("source") for t in techs), "every technology needs a source"


def test_technology_findings_old_nginx_php_gives_three():
    mod = tech_mod()
    techs = mod.detect_technology(load("responses", "old_nginx_php"))
    found = mod.technology_findings(techs)
    assert len(found) == 3
    assert rules(found) == {
        "tech.server_version_disclosed",
        "tech.powered_by_disclosed",
        "tech.generator_version_disclosed",
    }
    for finding in found:
        validate_raw_finding(finding)


def test_technology_findings_of_nothing_is_empty():
    assert tech_mod().technology_findings([]) == []


def test_technology_http_only_page_has_no_technology():
    assert tech_mod().detect_technology(load("responses", "http_only")) == []


@pytest.mark.parametrize("bad", [None, "text", 42])
def test_technology_bad_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        tech_mod().detect_technology(bad)


# ================================================================ HTTPS certificates

@pytest.mark.parametrize(
    "name, expected",
    [
        ("valid", set()),
        ("expired", {"https.cert_expired"}),
        ("expiring_soon", {"https.cert_expiring_soon"}),
        ("self_signed", {"https.cert_self_signed"}),
        ("hostname_mismatch", {"https.cert_hostname_mismatch"}),
    ],
)
def test_cert_fixtures_give_exactly_the_expected_rule(name, expected):
    found = run_cert(load("certs", name))
    assert rules(found) == expected
    assert len(found) == len(expected)


@pytest.mark.parametrize(
    "not_after, expected",
    [
        ("2026-11-19T00:00:00Z", {"https.cert_expiring_soon"}),  # exactly 30 days: "30 days or less"
        ("2026-11-20T00:00:00Z", set()),                          # 31 days
        ("2026-10-20T00:00:01Z", {"https.cert_expiring_soon"}),  # one second left: not yet expired
        ("2026-10-19T23:59:59Z", {"https.cert_expired"}),         # one second ago
    ],
)
def test_cert_expiry_boundaries(not_after, expected):
    info = load("certs", "valid")
    info["not_after"] = not_after
    assert rules(run_cert(info)) == expected


def test_cert_result_depends_only_on_the_given_time():
    info = load("certs", "valid")
    assert run_cert(info, now="2026-10-20T00:00:00Z") == []
    assert rules(run_cert(info, now="2027-02-01T00:00:00Z")) == {"https.cert_expired"}


def test_cert_findings_are_valid_raw_findings():
    for name in ("expired", "expiring_soon", "self_signed", "hostname_mismatch"):
        for finding in run_cert(load("certs", name)):
            validate_raw_finding(finding)


def test_cert_does_not_change_its_input():
    info = load("certs", "expired")
    before = copy.deepcopy(info)
    run_cert(info)
    assert info == before


@pytest.mark.parametrize("bad", [None, "text", 42])
def test_cert_bad_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        run_cert(bad)


# ================================================================ risky ports

@pytest.mark.parametrize(
    "port, service, rule",
    [
        (3306, "mysql", "ports.database_exposed"),
        (5432, "postgresql", "ports.database_exposed"),
        (27017, "mongodb", "ports.database_exposed"),
        (6379, "redis", "ports.database_exposed"),
        (3389, "ms-wbt-server", "ports.remote_desktop_exposed"),
        (5900, "vnc", "ports.remote_desktop_exposed"),
        (23, "telnet", "ports.telnet_exposed"),
        (21, "ftp", "ports.ftp_exposed"),
        (445, "microsoft-ds", "ports.smb_exposed"),
        (139, "netbios-ssn", "ports.smb_exposed"),
        (22, "ssh", "ports.ssh_exposed"),
        (5601, "kibana", "ports.admin_interface_exposed"),
    ],
)
def test_risky_port_gives_the_expected_rule(port, service, rule):
    found = run_ports(port, service)
    assert rules(found) == {rule}
    assert found[0]["ip"] == "203.0.113.10" and found[0]["port"] == port
    validate_raw_finding(found[0])


@pytest.mark.parametrize("port, service", [(80, "http"), (443, "https"), (8080, "http-proxy")])
def test_normal_web_ports_are_not_flagged(port, service):
    assert run_ports(port, service) == []


def test_no_open_ports_gives_nothing():
    assert ports_mod().check_risky_ports([]) == []
    assert ports_mod().check_risky_ports([{"ip": "203.0.113.10", "open_ports": []}]) == []


@pytest.mark.parametrize("bad", [None, "text", 42])
def test_ports_bad_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        ports_mod().check_risky_ports(bad)
