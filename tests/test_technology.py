"""Technology detection uses saved examples only; all sockets are blocked."""

import copy
import json
import socket
from pathlib import Path

import pytest

from exposureiq.fingerprint.contract import MAX_BODY_BYTES, validate_raw_finding
from exposureiq.fingerprint.technology import detect_technology, technology_findings
from exposureiq.storage import build_scan, load_scan, save_scan

FIXTURES = Path(__file__).parent / "fixtures" / "responses"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("technology detection must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def response(headers=None, body=""):
    return {
        "host": "example.com", "url": "https://example.com/", "scheme": "https",
        "status": 200, "headers": {} if headers is None else headers, "body": body,
    }


def load(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def test_old_nginx_php_has_exact_technologies_and_three_valid_findings():
    technologies = detect_technology(load("old_nginx_php"))
    assert technologies == [
        {"name": "nginx", "version": "1.18.0", "source": "Server header"},
        {"name": "php", "version": "8.1.2", "source": "X-Powered-By header"},
        {"name": "wordpress", "version": "6.4.2", "source": "HTML generator meta tag"},
    ]
    findings = technology_findings(technologies)
    assert [finding["rule"] for finding in findings] == [
        "tech.server_version_disclosed", "tech.powered_by_disclosed", "tech.generator_version_disclosed",
    ]
    for finding in findings:
        validate_raw_finding(finding)


@pytest.mark.parametrize("name", ["well_configured", "http_only", "bare_minimum"])
def test_fixtures_without_product_hints_are_empty(name):
    assert detect_technology(load(name)) == []


@pytest.mark.parametrize("header, value, name, version, source", [
    ("Server", "Apache/2.4.41 (Ubuntu)", "apache", "2.4.41", "Server header"),
    ("SERVER", " NGINX/1.18.0 ", "nginx", "1.18.0", "Server header"),
    ("server", "Microsoft-IIS/10.0", "microsoft-iis", "10.0", "Server header"),
    ("X-Powered-By", "PHP/8.1.2-1ubuntu2", "php", "8.1.2-1ubuntu2", "X-Powered-By header"),
    ("x-powered-by", "Express", "express", "", "X-Powered-By header"),
    ("x-powered-by", "ASP.NET", "asp.net", "", "X-Powered-By header"),
    ("server", "Apache (Ubuntu)", "apache", "", "Server header"),
    ("server", "nginx/latest", "nginx", "", "Server header"),
    ("server", "Apache / 2.4.41", "apache", "2.4.41", "Server header"),
])
def test_header_product_version_and_case(header, value, name, version, source):
    assert detect_technology(response({header: value})) == [
        {"name": name, "version": version, "source": source},
    ]


@pytest.mark.parametrize("body", [
    '<meta name="generator" content="WordPress/6.4.2">',
    "<META CONTENT='WORDPRESS 6.4.2' NAME='GeNeRaToR' />",
    '<html><head><meta content="WordPress&#32;6.4.2" name="generator"></head></html>',
    '<meta name=generator content="WordPress 6.4.2">',
])
def test_generator_tag_attribute_order_case_and_html_entities(body):
    assert detect_technology(response(body=body)) == [
        {"name": "wordpress", "version": "6.4.2", "source": "HTML generator meta tag"},
    ]


@pytest.mark.parametrize("body", [
    '<!-- <meta name="generator" content="WordPress 6.4.2"> -->',
    '<script>const tag = \'<meta name="generator" content="WordPress 6.4.2">\';</script>',
    '<meta name="description" content="WordPress 6.4.2">',
    '<meta name="generator">',
    '<meta name="generator" content="">',
    '<meta name="generator" content="123">',
])
def test_non_generator_or_hidden_hints_are_ignored(body):
    assert detect_technology(response(body=body)) == []


def test_product_without_version_is_not_a_finding_and_round_trips(tmp_path):
    technologies = detect_technology(response({"server": "nginx", "x-powered-by": "Express"},
                                              '<meta name="generator" content="WordPress">'))
    assert len(technologies) == 3
    assert all(technology["version"] == "" for technology in technologies)
    assert technology_findings(technologies) == []
    scan = build_scan("example.com", [{"host": "example.com", "ips": [], "technologies": technologies}])
    path = tmp_path / "scan.json"
    save_scan(scan, str(path))
    assert load_scan(str(path)) == scan


def test_generator_duplicates_and_duplicate_findings_are_removed():
    tag = '<meta name="generator" content="WordPress 6.4.2">'
    technologies = detect_technology(response(body=tag * 3))
    assert len(technologies) == 1
    assert len(technology_findings(technologies * 2)) == 1


def test_same_product_in_two_sources_keeps_both_sources():
    technologies = detect_technology(response({"server": "PHP/8.1.2", "x-powered-by": "PHP/8.1.2"}))
    assert len(technologies) == 2
    assert len(technology_findings(technologies)) == 2


def test_input_is_not_changed():
    data = load("old_nginx_php")
    before = copy.deepcopy(data)
    technologies = detect_technology(data)
    technologies_before = copy.deepcopy(technologies)
    technology_findings(technologies)
    assert data == before
    assert technologies == technologies_before


def test_body_is_limited_to_100kb():
    tag = '<meta name="generator" content="WordPress 6.4.2">'
    assert detect_technology(response(body="a" * MAX_BODY_BYTES + tag)) == []
    assert len(detect_technology(response(body="a" * (MAX_BODY_BYTES - len(tag)) + tag))) == 1


def test_body_limit_counts_utf8_bytes_not_characters():
    tag = '<meta name="generator" content="WordPress 6.4.2">'
    assert detect_technology(response(body="é" * (MAX_BODY_BYTES // 2) + tag)) == []
    assert len(detect_technology(response(body="é" * 100 + tag))) == 1


def test_malformed_large_html_and_long_product_are_bounded():
    assert detect_technology(response(body='<meta name="generator" content="' + "<" * 200000)) == []
    assert detect_technology(response({"server": "a" * 200000})) == []


@pytest.mark.parametrize("bad", [None, "text", 42, [], [response()]])
def test_non_dict_response_raises_value_error(bad):
    with pytest.raises(ValueError, match="dict"):
        detect_technology(bad)


@pytest.mark.parametrize("bad", [None, "text", [], 42])
def test_non_dict_headers_raise_value_error(bad):
    with pytest.raises(ValueError, match="headers"):
        detect_technology(response(bad) if bad is not None else {"headers": None})


@pytest.mark.parametrize("headers", [{"server": None}, {42: "nginx"}, {"server": 42}])
def test_non_string_header_names_and_values_raise_value_error(headers):
    with pytest.raises(ValueError, match="string"):
        detect_technology(response(headers))


@pytest.mark.parametrize("body", [None, 42, []])
def test_non_string_body_raises_value_error(body):
    with pytest.raises(ValueError, match="body"):
        detect_technology(response(body=body))


@pytest.mark.parametrize("bad", [None, "text", 42, [None], [{"name": "nginx", "version": None, "source": "Server header"}]])
def test_bad_technology_input_raises_value_error(bad):
    with pytest.raises(ValueError):
        technology_findings(bad)


def test_empty_technologies_and_unrecognized_source_have_no_findings():
    assert technology_findings([]) == []
    assert technology_findings([{"name": "nginx", "version": "1.18.0", "source": "unknown"}]) == []
