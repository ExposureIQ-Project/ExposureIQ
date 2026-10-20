"""Safety tests: nothing is sent out of scope, scope errors fail closed, pure checks
need no network, and files are clean (no BOM, no CRLF).

Network is blocked with the `no_network` fixture. It also RECORDS every attempt,
so a check that catches the error and carries on is still caught.

ASSUMPTION to confirm with Zaghlol: run_checks(assets) takes a list of assets like
{"host": ..., "ips": [...]}. If it differs, change only call_runner() below.
"""

import importlib
import json
import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
NOW = "2026-10-20T00:00:00Z"
HOST = "anything.example.net"


def load(kind, name):
    return json.loads((FIXTURES / kind / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def no_network(monkeypatch):
    """Block sockets. Returns the list of blocked attempts (must stay empty)."""
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    return attempts


def deny_scope(host):
    return False


def broken_scope(host):
    raise RuntimeError("scope file unreadable")


def set_scope(monkeypatch, module, behaviour):
    """The module under test must import is_in_scope at its top (shared rule 3)."""
    assert hasattr(module, "is_in_scope"), (
        f"{module.__name__} must do 'from exposureiq.discovery.scope import is_in_scope' at the top"
    )
    monkeypatch.setattr(module, "is_in_scope", behaviour)
    try:
        scope = importlib.import_module("exposureiq.discovery.scope")
        monkeypatch.setattr(scope, "is_in_scope", behaviour)
    except ImportError:
        pass


def call_runner(runner):
    assets = [{
        "host": HOST,
        "ips": [{"ip": "203.0.113.10", "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}]}],
    }]
    return runner.run_checks(assets)


def patch_everywhere(monkeypatch, behaviour):
    """Replace is_in_scope in every module that sends traffic (the runner may use any)."""
    patched = 0
    for name in ("web", "https_checks", "runner"):
        try:
            module = importlib.import_module(f"exposureiq.fingerprint.{name}")
        except ImportError:
            continue
        if hasattr(module, "is_in_scope"):
            set_scope(monkeypatch, module, behaviour)
            patched += 1
    return patched


# ================================================================ the guard itself

def test_no_network_fixture_really_blocks_and_records(no_network):
    with pytest.raises(AssertionError, match="network used"):
        socket.create_connection(("192.0.2.1", 80))
    assert len(no_network) == 1


# ================================================================ out of scope: nothing is sent

@pytest.mark.parametrize("behaviour", [deny_scope, broken_scope], ids=["out_of_scope", "scope_error"])
def test_fetch_front_page_sends_nothing(monkeypatch, no_network, behaviour):
    web = pytest.importorskip("exposureiq.fingerprint.web")
    set_scope(monkeypatch, web, behaviour)
    assert web.fetch_front_page(HOST) is None
    assert no_network == []


@pytest.mark.parametrize("behaviour", [deny_scope, broken_scope], ids=["out_of_scope", "scope_error"])
def test_get_certificate_info_sends_nothing(monkeypatch, no_network, behaviour):
    https = pytest.importorskip("exposureiq.fingerprint.https_checks")
    set_scope(monkeypatch, https, behaviour)
    assert https.get_certificate_info(HOST) is None
    assert no_network == []


@pytest.mark.parametrize("behaviour", [deny_scope, broken_scope], ids=["out_of_scope", "scope_error"])
def test_runner_sends_nothing(monkeypatch, no_network, behaviour):
    runner = pytest.importorskip("exposureiq.fingerprint.runner")
    pytest.importorskip("exposureiq.fingerprint.web")
    assert patch_everywhere(monkeypatch, behaviour) >= 1, "no module imports is_in_scope"
    call_runner(runner)  # must not raise AssertionError("network used")
    assert no_network == []


# ================================================================ pure checks need no network

def test_pure_header_and_technology_checks_work_offline(no_network):
    headers = pytest.importorskip("exposureiq.fingerprint.headers")
    tech = pytest.importorskip("exposureiq.fingerprint.technology")
    resp = load("responses", "old_nginx_php")
    headers.check_security_headers(resp)
    tech.technology_findings(tech.detect_technology(resp))
    assert no_network == []


def test_pure_certificate_check_works_offline(no_network):
    https = pytest.importorskip("exposureiq.fingerprint.https_checks")
    https.analyze_certificate(load("certs", "expired"), now=NOW)
    assert no_network == []


def test_pure_ports_check_works_offline(no_network):
    ports = pytest.importorskip("exposureiq.fingerprint.risky_ports")
    ips = [{"ip": "203.0.113.10", "open_ports": [{"port": 3306, "protocol": "tcp", "service": "mysql"}]}]
    assert ports.check_risky_ports(ips)
    assert no_network == []


# ================================================================ file hygiene (BOM / CRLF)

def hygiene_files():
    files = []
    for folder in (ROOT / "exposureiq" / "fingerprint", ROOT / "tests" / "fixtures"):
        if folder.exists():
            files += [p for p in folder.rglob("*") if p.suffix in (".py", ".json")]
    return sorted(files)


def test_hygiene_finds_the_files_it_should_check():
    assert any(p.suffix == ".json" for p in hygiene_files())
    assert any(p.name == "contract.py" for p in hygiene_files())


def test_no_file_has_a_bom():
    bad = [str(p.relative_to(ROOT)) for p in hygiene_files() if p.read_bytes().startswith(b"\xef\xbb\xbf")]
    assert bad == [], f"BOM found in: {bad}"


def test_no_file_has_crlf_line_endings():
    bad = [str(p.relative_to(ROOT)) for p in hygiene_files() if b"\r\n" in p.read_bytes()]
    assert bad == [], f"CRLF found in: {bad}"


def test_every_file_is_valid_utf8():
    for path in hygiene_files():
        path.read_bytes().decode("utf-8")


# ================================================================ every rule ID exists in RULES

ALL_RULES = {
    "headers.missing_hsts", "headers.weak_hsts", "headers.missing_csp", "headers.weak_csp",
    "headers.missing_x_content_type_options", "headers.missing_clickjacking_protection",
    "headers.missing_referrer_policy", "headers.missing_permissions_policy",
    "tech.server_version_disclosed", "tech.powered_by_disclosed", "tech.generator_version_disclosed",
    "https.not_available", "https.cert_expired", "https.cert_expiring_soon",
    "https.cert_hostname_mismatch", "https.cert_self_signed", "https.cert_untrusted",
    "ports.database_exposed", "ports.remote_desktop_exposed", "ports.telnet_exposed",
    "ports.ftp_exposed", "ports.smb_exposed", "ports.ssh_exposed", "ports.admin_interface_exposed",
}  # https.old_tls_supported is a stretch rule, so it is not required


def get_rules():
    severity = pytest.importorskip("exposureiq.fingerprint.severity")
    return severity.RULES


def test_severity_has_every_required_rule():
    missing = sorted(ALL_RULES - set(get_rules()))
    assert missing == [], f"severity.py RULES is missing: {missing}"


def test_every_rule_returned_by_a_check_exists_in_rules():
    known = set(get_rules())
    produced = set()

    headers = pytest.importorskip("exposureiq.fingerprint.headers")
    for name in ("well_configured", "bare_minimum", "old_nginx_php", "http_only"):
        produced |= {f["rule"] for f in headers.check_security_headers(load("responses", name))}

    tech = pytest.importorskip("exposureiq.fingerprint.technology")
    techs = tech.detect_technology(load("responses", "old_nginx_php"))
    produced |= {f["rule"] for f in tech.technology_findings(techs)}

    https = pytest.importorskip("exposureiq.fingerprint.https_checks")
    for name in ("valid", "expired", "expiring_soon", "self_signed", "hostname_mismatch"):
        produced |= {f["rule"] for f in https.analyze_certificate(load("certs", name), now=NOW)}

    ports = pytest.importorskip("exposureiq.fingerprint.risky_ports")
    for port in (21, 22, 23, 139, 445, 3306, 3389, 5601, 5900, 6379):
        ips = [{"ip": "203.0.113.10", "open_ports": [{"port": port, "protocol": "tcp", "service": "x"}]}]
        produced |= {f["rule"] for f in ports.check_risky_ports(ips)}

    assert produced, "no check produced any finding"
    assert sorted(produced - known) == []
