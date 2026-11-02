"""Tests for pure scan comparison and removal presence checks."""

import copy

from exposureiq.diffing.compare import change_key, compare_scans, present_in


def scan(*assets, target="example.com", started="2026-10-01T00:00:00Z", scan_id="S1"):
    return {
        "schema_version": "0.2",
        "scan_id": scan_id,
        "target": target,
        "started_at": started,
        "assets": list(assets),
    }


def asset(host, ips=None, technologies=None, findings=None):
    return {
        "host": host,
        "ips": ips or [],
        "technologies": technologies or [],
        "findings": findings or [],
    }


def ip(address, ports=None):
    return {"ip": address, "open_ports": ports or []}


def port(number, service="https", protocol="tcp"):
    return {"port": number, "protocol": protocol, "service": service}


def tech(name, version="", source="Server header"):
    return {"name": name, "version": version, "source": source}


def finding(rule, severity="medium", title="Issue", ip_address=None, port_number=None):
    result = {
        "id": "F-0001", "rule": rule, "check": "security_headers",
        "severity": severity, "title": title, "detail": "detail",
        "recommendation": "fix it",
    }
    if ip_address:
        result["ip"] = ip_address
    if port_number:
        result["port"] = port_number
    return result


def kinds(diff):
    return [change["kind"] for change in diff["changes"]]


def test_host_added_and_removed():
    before = scan(asset("old.example.com"), asset("same.example.com"))
    after = scan(asset("new.example.com"), asset("same.example.com"))
    result = compare_scans(before, after)

    assert kinds(result) == ["host.new", "host.removed"]
    added = result["changes"][0]
    assert added["host"] == "new.example.com"
    assert added["status"] == "new" and added["direction"] == "worse"
    removed = result["changes"][1]
    assert removed["host"] == "old.example.com"
    assert removed["status"] == "missing" and removed["direction"] == "better"


def test_host_names_are_matched_case_insensitively():
    result = compare_scans(scan(asset("WWW.Example.com")), scan(asset("www.example.com")))
    assert result["changes"] == []


def test_ip_added_and_removed_belong_to_the_host():
    before = scan(asset("www.example.com", [ip("203.0.113.1")]))
    after = scan(asset("www.example.com", [ip("203.0.113.2")]))
    result = compare_scans(before, after)

    assert kinds(result) == ["ip.new", "ip.removed"]
    assert result["changes"][1]["host"] == "www.example.com"
    assert result["changes"][1]["ip"] == "203.0.113.1"


def test_ports_open_close_and_change_service():
    before = scan(asset("www.example.com", [ip("203.0.113.1", [
        port(80, "http"), port(443, "https"), port(22, "ssh"),
    ])]))
    after = scan(asset("www.example.com", [ip("203.0.113.1", [
        port(80, "http-alt"), port(443, "https"), port(8443, "https-alt"),
    ])]))
    result = compare_scans(before, after)

    assert kinds(result) == ["port.opened", "port.closed", "port.service_changed"]
    assert result["changes"][0]["port"] == 8443
    assert result["changes"][1]["port"] == 22
    assert result["changes"][1]["status"] == "missing"
    assert result["changes"][2]["port"] == 80
    assert result["changes"][2]["before"]["service"] == "http"
    assert result["changes"][2]["after"]["service"] == "http-alt"


def test_technologies_added_removed_and_version_changed():
    before = scan(asset("www.example.com", technologies=[
        tech("nginx", "1.18.0"), tech("php", "8.1", "X-Powered-By header"),
    ]))
    after = scan(asset("www.example.com", technologies=[
        tech("nginx", "1.24.0"), tech("react", "", "HTML generator meta tag"),
    ]))
    result = compare_scans(before, after)

    assert kinds(result) == ["tech.new", "tech.removed", "tech.version_changed"]
    assert result["changes"][0]["after"]["technology"] == "react"
    assert result["changes"][1]["before"]["technology"] == "php"
    assert result["changes"][2]["before"]["version"] == "1.18.0"
    assert result["changes"][2]["after"]["version"] == "1.24.0"


def test_findings_use_rule_not_the_per_scan_id():
    before = scan(asset("www.example.com", findings=[
        finding("headers.missing_csp", "medium", ip_address="203.0.113.1"),
    ]))
    after = scan(asset("www.example.com", findings=[
        {**finding("headers.missing_csp", "medium", ip_address="203.0.113.1"), "id": "F-0099"},
    ]))
    assert compare_scans(before, after)["changes"] == []


def test_findings_new_resolved_and_severity_changed():
    before = scan(asset("www.example.com", findings=[
        finding("headers.missing_csp", "medium"),
        finding("https.cert_expired", "high", ip_address="203.0.113.1"),
    ]))
    after = scan(asset("www.example.com", findings=[
        finding("headers.missing_csp", "high"),
        finding("ports.ftp_exposed", "medium", ip_address="203.0.113.2", port_number=21),
    ]))
    result = compare_scans(before, after)

    assert kinds(result) == [
        "finding.new", "finding.resolved", "finding.severity_changed",
    ]
    assert result["changes"][0]["after"]["rule"] == "ports.ftp_exposed"
    assert result["changes"][1]["before"]["rule"] == "https.cert_expired"
    assert result["changes"][2]["direction"] == "worse"
    assert result["changes"][2]["before"]["severity"] == "medium"
    assert result["changes"][2]["after"]["severity"] == "high"


def test_compare_does_not_mutate_inputs():
    before = scan(asset("old.example.com", [ip("203.0.113.1", [port(80, "http")])],
                       [tech("nginx", "1.0")], [finding("headers.missing_csp")]))
    after = scan(asset("new.example.com", [ip("203.0.113.2", [port(443, "https")])],
                       [tech("nginx", "2.0")], [finding("headers.missing_hsts")]))
    original = copy.deepcopy((before, after))
    compare_scans(before, after)
    assert (before, after) == original


def test_result_includes_both_scan_metadata_blocks():
    result = compare_scans(
        scan(started="2026-10-01T00:00:00Z", scan_id="OLD"),
        scan(started="2026-10-02T00:00:00Z", scan_id="NEW"),
    )
    assert result["target"] == "example.com"
    assert result["old"]["scan_id"] == "OLD"
    assert result["new"]["scan_id"] == "NEW"


def removal(kind, **extra):
    base = {
        "kind": kind, "host": "www.example.com", "ip": None, "port": None,
        "before": {}, "after": None, "status": "missing",
    }
    base.update(extra)
    return base


def test_present_in_host():
    current = scan(asset("www.example.com"))
    assert present_in(current, removal("host.removed")) is True
    assert present_in(scan(asset("other.example.com")), removal("host.removed")) is False


def test_present_in_ip():
    current = scan(asset("www.example.com", [ip("203.0.113.1")]))
    change = removal("ip.removed", ip="203.0.113.1")
    assert present_in(current, change) is True
    assert present_in(current, removal("ip.removed", ip="203.0.113.9")) is False


def test_present_in_port():
    current = scan(asset("www.example.com", [ip("203.0.113.1", [port(443, "https")])]))
    change = removal("port.closed", ip="203.0.113.1", port=443,
                     before={"port": 443, "protocol": "tcp", "service": "https"})
    assert present_in(current, change) is True
    closed = removal("port.closed", ip="203.0.113.1", port=22,
                     before={"port": 22, "protocol": "tcp", "service": "ssh"})
    assert present_in(current, closed) is False


def test_present_in_technology():
    current = scan(asset("www.example.com", technologies=[tech("nginx", "1.0")]))
    change = removal("tech.removed", before={"technology": "nginx", "source": "Server header"})
    assert present_in(current, change) is True
    missing = removal("tech.removed", before={"technology": "php", "source": "X-Powered-By header"})
    assert present_in(current, missing) is False


def test_present_in_finding():
    current = scan(asset("www.example.com", findings=[finding("headers.missing_csp")]))
    change = removal("finding.resolved", before=finding("headers.missing_csp"))
    assert present_in(current, change) is True
    other = removal("finding.resolved", before=finding("headers.missing_hsts"))
    assert present_in(current, other) is False


def test_change_key_is_stable_across_finding_ids():
    first = removal("finding.resolved", before=finding("headers.missing_csp"))
    second = removal("finding.resolved", before={**finding("headers.missing_csp"), "id": "F-0042"})
    assert change_key(first) == change_key(second)
