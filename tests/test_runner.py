"""Runner unit tests fake the fetch/certificate functions and block all sockets.

For a REAL, offline loopback demo (not a pytest test), run from the project root:
    PYTHONPATH=. python tests/test_runner.py --local-demo
It starts a front-page server on 127.0.0.1, checks it with the real runner, shows
the terminal tables, and saves/loads schema 0.2 JSON in a temporary directory.
"""

import copy
import json
import socket
from pathlib import Path

import pytest

from exposureiq.fingerprint import https_checks, runner, web
from exposureiq.fingerprint.contract import validate_finding
from exposureiq.storage import build_scan, load_scan, save_scan

FIXTURES = Path(__file__).parent / "fixtures"


def load(kind, name):
    return json.loads((FIXTURES / kind / f"{name}.json").read_text(encoding="utf-8"))


def asset(host="api.example.com", ports=None):
    return {"host": host, "ips": [{"ip": "203.0.113.10", "open_ports": [] if ports is None else ports}]}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("runner unit tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    yield attempts
    # Even swallowed connection errors must fail a unit test.
    assert attempts == []


@pytest.fixture
def fake_stages(monkeypatch):
    calls = {"fetch": [], "certificate": []}

    def fetch(host):
        calls["fetch"].append(host)
        response = load("responses", "old_nginx_php")
        response.update(host=host, url=f"https://{host}/")
        return response

    def certificate(host, *args, **kwargs):
        calls["certificate"].append(host)
        info = load("certs", "valid")
        info.update(host=host, subject=host, san=[host], not_after="2999-01-01T00:00:00Z")
        return info

    monkeypatch.setattr(runner, "is_in_scope", lambda host: True)
    monkeypatch.setattr(runner, "fetch_front_page", fetch)
    monkeypatch.setattr(https_checks, "get_certificate_info", certificate)
    return calls


def test_runner_annotates_same_assets_and_all_results_validate(fake_stages):
    assets = [asset(ports=[{"port": 3306, "protocol": "tcp", "service": "mysql"}])]
    ips_before = copy.deepcopy(assets[0]["ips"])
    result = runner.run_checks(assets)
    assert result is assets
    assert assets[0]["ips"] == ips_before
    assert len(assets[0]["technologies"]) == 3
    findings = assets[0]["findings"]
    assert len(findings) == 10  # six headers, three disclosed versions, one database port
    assert [finding["id"] for finding in findings] == [f"F-{number:04d}" for number in range(1, 11)]
    for finding in findings:
        validate_finding(finding)
    assert findings[-1]["severity"] == "high"
    assert findings[-1]["ip"] == "203.0.113.10" and findings[-1]["port"] == 3306
    assert fake_stages == {"fetch": ["api.example.com"], "certificate": ["api.example.com"]}


def test_findings_ids_continue_across_hosts(fake_stages):
    assets = [asset("api.example.com"), asset("www.example.com")]
    runner.run_checks(assets)
    assert assets[0]["findings"][0]["id"] == "F-0001"
    assert assets[1]["findings"][0]["id"] == "F-0010"
    ids = [finding["id"] for entry in assets for finding in entry["findings"]]
    assert ids == [f"F-{number:04d}" for number in range(1, 19)]
    assert fake_stages["fetch"] == ["api.example.com", "www.example.com"]


def test_well_configured_host_has_empty_lists(monkeypatch, fake_stages):
    monkeypatch.setattr(runner, "fetch_front_page", lambda host: load("responses", "well_configured"))
    assets = [asset()]
    runner.run_checks(assets)
    assert assets[0]["technologies"] == [] and assets[0]["findings"] == []


@pytest.mark.parametrize("behaviour", ["deny", "raise", "missing", "none", "truthy"])
def test_scope_gate_runs_before_any_fetch_or_tls(monkeypatch, fake_stages, behaviour, caplog):
    def broken(host):
        raise RuntimeError("scope file unreadable")

    if behaviour == "missing":
        monkeypatch.delattr(runner, "is_in_scope")
    else:
        checker = {
            "deny": lambda host: False, "raise": broken,
            "none": lambda host: None, "truthy": lambda host: "yes",
        }[behaviour]
        monkeypatch.setattr(runner, "is_in_scope", checker)
    assets = [asset()]
    assets[0].update(technologies=[{"old": "hint"}], findings=[{"old": "finding"}])
    assert runner.run_checks(assets) is assets
    assert assets[0]["technologies"] == [] and assets[0]["findings"] == []
    assert fake_stages == {"fetch": [], "certificate": []}
    assert "scope" in caplog.text


def test_one_scope_failure_does_not_stop_later_hosts(monkeypatch, fake_stages):
    def scope(host):
        if host == "bad.example.com":
            raise OSError("scope unreadable")
        return host == "good.example.com"

    monkeypatch.setattr(runner, "is_in_scope", scope)
    assets = [asset("bad.example.com"), asset("out.example.com"), asset("good.example.com")]
    runner.run_checks(assets)
    assert all(entry["findings"] == [] for entry in assets[:2])
    assert assets[2]["findings"][0]["id"] == "F-0001"
    assert fake_stages == {"fetch": ["good.example.com"], "certificate": ["good.example.com"]}


@pytest.mark.parametrize("stage", [
    "fetch_front_page", "check_security_headers", "detect_technology", "technology_findings",
    "check_https", "check_risky_ports", "build_findings",
])
def test_any_host_stage_failure_is_isolated(monkeypatch, fake_stages, stage, caplog):
    module = runner.severity if stage == "build_findings" else runner
    original = getattr(module, stage)
    calls = []

    def first_fails(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("bad first host")
        return original(*args, **kwargs)

    monkeypatch.setattr(module, stage, first_fails)
    assets = [asset("bad.example.com"), asset("good.example.com")]
    assert runner.run_checks(assets) is assets
    assert assets[0]["technologies"] == [] and assets[0]["findings"] == []
    assert assets[1]["findings"][0]["id"] == "F-0001"
    assert len(assets[1]["technologies"]) == 3
    assert "Checks failed for bad.example.com" in caplog.text


def test_none_response_does_not_invent_missing_headers(monkeypatch, fake_stages):
    monkeypatch.setattr(runner, "fetch_front_page", lambda host: None)
    monkeypatch.setattr(https_checks, "get_certificate_info", lambda host: None)
    assets = [asset(ports=[{"port": 22, "protocol": "tcp", "service": "ssh"}])]
    runner.run_checks(assets)
    assert assets[0]["technologies"] == []
    assert [finding["rule"] for finding in assets[0]["findings"]] == ["ports.ssh_exposed"]


def test_http_only_response_gets_https_not_available(monkeypatch, fake_stages):
    monkeypatch.setattr(runner, "fetch_front_page", lambda host: load("responses", "http_only"))
    monkeypatch.setattr(https_checks, "get_certificate_info", lambda host: None)
    assets = [asset()]
    runner.run_checks(assets)
    rules = {finding["rule"] for finding in assets[0]["findings"]}
    assert "https.not_available" in rules and "headers.missing_hsts" not in rules
    assert len(rules) == 6
    assert next(f for f in assets[0]["findings"] if f["rule"] == "https.not_available")["severity"] == "high"


def test_certificate_check_still_runs_when_web_does_not_answer(monkeypatch, fake_stages):
    monkeypatch.setattr(runner, "fetch_front_page", lambda host: None)
    info = load("certs", "expired")
    monkeypatch.setattr(https_checks, "get_certificate_info", lambda host: info)
    assets = [asset()]
    runner.run_checks(assets)
    assert [finding["rule"] for finding in assets[0]["findings"]] == ["https.cert_expired"]


def test_exact_duplicate_findings_are_removed_before_ids(monkeypatch, fake_stages):
    raw = {"rule": "headers.missing_csp", "detail": "No CSP"}
    monkeypatch.setattr(runner, "check_security_headers", lambda response: [raw, dict(raw), dict(raw)])
    monkeypatch.setattr(runner, "detect_technology", lambda response: [])
    assets = [asset()]
    runner.run_checks(assets)
    assert len(assets[0]["findings"]) == 1
    assert assets[0]["findings"][0]["id"] == "F-0001"


def test_distinct_ip_port_evidence_is_not_removed(monkeypatch, fake_stages):
    ports = [{"port": 3306, "protocol": "tcp", "service": "mysql"},
             {"port": 5432, "protocol": "tcp", "service": "postgresql"}]
    assets = [asset(ports=ports)]
    assets[0]["ips"].append({"ip": "192.0.2.10", "open_ports": ports})
    runner.run_checks(assets)
    findings = [finding for finding in assets[0]["findings"] if finding["rule"] == "ports.database_exposed"]
    assert {(finding["ip"], finding["port"]) for finding in findings} == {
        ("203.0.113.10", 3306), ("203.0.113.10", 5432), ("192.0.2.10", 3306), ("192.0.2.10", 5432),
    }


def test_unknown_and_invalid_raw_findings_are_logged_and_skipped(monkeypatch, fake_stages, caplog):
    raw = [{"rule": "headers.future_rule", "detail": "Unknown check"}, None,
           {"rule": "headers.missing_csp", "detail": "No CSP"}]
    monkeypatch.setattr(runner, "check_security_headers", lambda response: raw)
    monkeypatch.setattr(runner, "detect_technology", lambda response: [])
    assets = [asset()]
    runner.run_checks(assets)
    assert [finding["rule"] for finding in assets[0]["findings"]] == ["headers.missing_csp"]
    assert assets[0]["findings"][0]["id"] == "F-0001"
    assert "Unknown finding rule" in caplog.text and "Invalid check result" in caplog.text


def test_runner_results_save_and_load_without_format_changes(tmp_path, fake_stages):
    assets = runner.run_checks([asset()])
    scan = build_scan("example.com", assets, started_at="2026-10-20T00:00:00Z")
    path = tmp_path / "scan.json"
    save_scan(scan, str(path))
    assert load_scan(str(path)) == scan and scan["schema_version"] == "0.2"


@pytest.mark.parametrize("bad", [None, "text", 42, {}, ()])
def test_non_list_assets_never_raise(bad, no_network):
    assert runner.run_checks(bad) == []


@pytest.mark.parametrize("bad_host", [None, "", "  ", 42, []])
def test_invalid_host_never_fetches(monkeypatch, fake_stages, bad_host):
    assets = [asset(bad_host)]
    assert runner.run_checks(assets) is assets
    assert assets[0]["findings"] == []
    assert fake_stages == {"fetch": [], "certificate": []}


def test_malformed_asset_entries_do_not_stop_later_hosts(fake_stages):
    assets = [None, "text", 42, {}, asset()]
    assert runner.run_checks(assets) is assets
    assert assets[3] == {"technologies": [], "findings": []}
    assert assets[-1]["findings"][0]["id"] == "F-0001"


def test_front_page_redirects_are_not_followed_and_limit_is_restored(monkeypatch, fake_stages):
    calls = []

    def redirect(url, timeout):
        calls.append(url)
        return {"url": url, "scheme": "https", "status": 302,
                "headers": {"location": "/login"}, "body": ""}

    monkeypatch.setattr(web, "is_in_scope", lambda host: True)
    monkeypatch.setattr(web, "_get_once", redirect)
    monkeypatch.setattr(runner, "fetch_front_page", web.fetch_front_page)
    previous = web.MAX_REDIRECTS
    runner.run_checks([asset()])
    assert calls == ["https://api.example.com/"]
    assert web.MAX_REDIRECTS == previous


def test_front_page_redirect_limit_is_restored_after_fetch_exception(monkeypatch, fake_stages):
    previous = web.MAX_REDIRECTS

    def boom(host):
        assert web.MAX_REDIRECTS == 0
        raise OSError("fetch failed")

    monkeypatch.setattr(runner, "fetch_front_page", boom)
    runner.run_checks([asset()])
    assert web.MAX_REDIRECTS == previous


def local_demo() -> int:
    """Real HTTP and TLS, only on loopback; never called by pytest.

    High ports are passed through the existing fetch/certificate interfaces, not
    through a scope bypass. The runner, checks, severity, output, and JSON storage
    are real. A network guard also rejects any non-loopback connection or DNS.
    """
    import ipaddress
    import logging
    import tempfile
    import threading
    from functools import partial
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from unittest.mock import patch

    from exposureiq import output

    host = "127.0.0.1"
    connections, requests_seen = [], []
    original_connect, original_getaddrinfo = socket.socket.connect, socket.getaddrinfo

    def loopback_only_connect(sock, address):
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise AssertionError(f"Demo refused non-loopback connection: {address}")
        connections.append(address)
        return original_connect(sock, address)

    def loopback_only_dns(name, *args, **kwargs):
        if not ipaddress.ip_address(name).is_loopback:
            raise AssertionError(f"Demo refused non-loopback DNS lookup: {name}")
        return original_getaddrinfo(name, *args, **kwargs)

    class FrontPage(BaseHTTPRequestHandler):
        server_version = "nginx/1.18.0"
        sys_version = ""

        def do_GET(self):
            requests_seen.append((self.path, self.headers.get("User-Agent", "")))
            if self.path != "/":
                self.send_error(404)
                return
            body = b'<html><head><meta name="generator" content="WordPress 6.4.2"></head><body>Local demo</body></html>'
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.1.2")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    # Reserve a closed HTTPS port throughout the demo so no other service is touched.
    with HTTPServer((host, 0), FrontPage) as server, socket.socket() as closed_tls_port:
        closed_tls_port.bind((host, 0))
        http_port = server.server_port
        https_port = closed_tls_port.getsockname()[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            temporary_root = Path("/tmp/opencode")
            directory = Path(tempfile.mkdtemp(prefix="exposureiq-stage2-demo-",
                                              dir=temporary_root if temporary_root.is_dir() else None))
            path = directory / "scan.json"
            logging.basicConfig(level=logging.WARNING, format="%(message)s")
            output.banner(host, "0.1.0 (offline loopback demo)")
            output.info(f"Real front-page server: http://{host}:{http_port}/")
            output.info("HTTPS is intentionally unavailable in this local example.")
            # Ignore proxy environment settings so even the transport stays local.
            with patch.dict("os.environ", {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}), \
                    patch.object(socket.socket, "connect", loopback_only_connect), \
                    patch.object(socket, "getaddrinfo", loopback_only_dns), \
                    patch.object(runner, "fetch_front_page", partial(web.fetch_front_page, timeout=2,
                                 http_port=http_port, https_port=https_port)), \
                    patch.object(https_checks, "get_certificate_info",
                                 partial(https_checks.get_certificate_info, port=https_port, timeout=2)):
                assets = runner.run_checks([{"host": host, "ips": [{"ip": host, "open_ports": []}]}])
            assert len(requests_seen) == 1 and requests_seen[0][0] == "/", requests_seen
            assert requests_seen[0][1].startswith("ExposureIQ/"), requests_seen
            assert connections and all(ipaddress.ip_address(address[0]).is_loopback for address in connections)
            assert len(assets[0]["technologies"]) == 3
            assert len(assets[0]["findings"]) == 9
            assert any(finding["rule"] == "https.not_available" for finding in assets[0]["findings"])
            for finding in assets[0]["findings"]:
                validate_finding(finding)
            output.technology_table(assets, 0)
            output.findings_table(assets, 0)
            scan = build_scan(host, assets)
            save_scan(scan, str(path))
            assert load_scan(str(path)) == scan
            output.summary([("Mode", "Real loopback only; no discovery or Nmap"),
                            ("Front-page GETs", len(requests_seen)), ("Technology hints", 3)], path, assets=assets)
            output.ok("Demo verified: 3 technologies, 9 findings, saved JSON loaded and validated.")
            return 0
        finally:
            server.shutdown()
            thread.join(timeout=3)


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--local-demo"]:
        raise SystemExit("Use PYTHONPATH=. python tests/test_runner.py --local-demo (only loopback traffic).")
    raise SystemExit(local_demo())
