"""End-to-end tests of the whole command in --demo mode, plus the safety rules.

All network sockets are blocked, so any accidental network access fails the test.

Run from the project root:   python -m pytest
"""
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from exposureiq import cli, demo_data

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access is not allowed in tests")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def no_real_discovery(monkeypatch):
    """Fail the test if real Subfinder/crt.sh discovery is ever used."""
    def forbidden(*args, **kwargs):
        pytest.fail("real discovery must not run in --demo mode")
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", forbidden)
    monkeypatch.setattr(cli.sub, "find_subdomains", forbidden)
    monkeypatch.setattr(cli, "resolve_hosts", forbidden)


def read(capsys):
    return " ".join(capsys.readouterr().out.split())


# --------------------------------------------------------------- demo mode --
def test_demo_workflow_is_offline_and_deterministic(no_real_discovery, tmp_path, capsys):
    storage = pytest.importorskip("exposureiq.storage")
    out = tmp_path / "scan.json"
    assert cli.main(["scan", "example.com", "--demo", "-o", str(out)]) == 0
    text = read(capsys)
    for number in range(1, 6):
        assert f"[{number}/5]" in text
    assert "DEMO MODE" in text and "DEMO (fake data)" in text
    assert "Found 4 subdomains" in text
    assert "1 had no DNS answer" in text                       # old.example.com is dead
    assert "only runs with --ports" in text                    # ports are opt-in

    scan = json.loads(out.read_text(encoding="utf-8"))
    assert [a["host"] for a in scan["assets"]] == [
        "example.com", "api.example.com", "mail.example.com", "www.example.com"]
    assert all(ip["ip"].startswith("192.0.2.") for a in scan["assets"] for ip in a["ips"])
    assert all(ip["open_ports"] == [] for a in scan["assets"] for ip in a["ips"])
    assert storage.load_scan(str(out)) == scan                 # valid according to the findings format


def test_demo_gives_identical_results_every_time(no_real_discovery, tmp_path):
    pytest.importorskip("exposureiq.storage")
    results = []
    for name in ("one.json", "two.json"):
        cli.main(["scan", "example.com", "--demo", "-o", str(tmp_path / name)])
        results.append(json.loads((tmp_path / name).read_text(encoding="utf-8"))["assets"])
    assert results[0] == results[1]


def test_demo_files_are_named_so_nobody_mistakes_them_for_real(no_real_discovery, tmp_path, monkeypatch):
    pytest.importorskip("exposureiq.storage")
    monkeypatch.chdir(tmp_path)
    cli.main(["scan", "example.com", "--demo"])
    files = list((tmp_path / "results").glob("*.json"))
    assert len(files) == 1 and files[0].name.startswith("demo_example.com_")


def test_demo_ports_only_with_flag_and_only_documentation_ips(no_real_discovery, tmp_path, monkeypatch):
    pytest.importorskip("exposureiq.storage")
    scanned = []
    monkeypatch.setattr(demo_data, "resolve_hosts", lambda hosts, **k: [
        {"host": "example.com", "ips": ["192.0.2.1"]},          # documentation range: allowed in demo
        {"host": "www.example.com", "ips": ["8.8.8.8"]},         # a real-looking IP: never scanned
    ])
    monkeypatch.setattr(demo_data, "scan_ports",
                        lambda ip: scanned.append(ip) or [{"port": 80, "protocol": "tcp", "service": "http"}])
    cli.main(["scan", "example.com", "--demo", "-o", str(tmp_path / "a.json")])
    assert scanned == []                                        # no --ports, no scan
    cli.main(["scan", "example.com", "--demo", "--ports", "-o", str(tmp_path / "b.json")])
    assert scanned == ["192.0.2.1"]                             # 8.8.8.8 was never scanned


def test_demo_does_not_confuse_people_with_a_scope_message(no_real_discovery, tmp_path, capsys):
    pytest.importorskip("exposureiq.storage")
    assert cli.main(["scan", "example.com", "--demo", "--require-scope", "--no-save"]) == 0
    text = read(capsys)
    assert "scope is not checked" in text and "not listed in scope.txt" not in text


def test_demo_scope_helper_is_strict():
    assert demo_data.is_in_scope("192.0.2.7") is True
    for bad in ("8.8.8.8", "192.0.3.1", "example.com", "", "not an ip"):
        assert demo_data.is_in_scope(bad) is False


def test_without_demo_the_real_discovery_is_used(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source",
                        lambda domain, **k: calls.append(domain) or {"subfinder": ["www.example.com"], "crtsh": []})
    monkeypatch.setattr(cli, "resolve_hosts", lambda hosts, **k: [])
    monkeypatch.setattr(cli, "_load_scope", lambda: (lambda target: False))
    cli.main(["scan", "example.com", "--no-save"])
    assert calls == ["example.com"]                             # real mode is the default


# ------------------------------------------------------ the real scope file --
def test_scan_still_refuses_ports_with_the_real_scope_module(monkeypatch, tmp_path, capsys):
    """Whatever scope module is merged, an IP that is not listed must never be port scanned."""
    scope = cli._load_scope()
    if scope is None:
        pytest.skip("no scope module merged yet")
    assert scope("8.8.8.8") is False                            # a public IP is not in the default scope.txt
    scanned = []
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", lambda d, **k: {"subfinder": [], "crtsh": []})
    monkeypatch.setattr(cli, "resolve_hosts", lambda hosts, **k: [{"host": "example.com", "ips": ["8.8.8.8"]}])
    monkeypatch.setattr(cli, "_load_ports", lambda: (lambda ip: scanned.append(ip) or [], scope))
    cli.main(["scan", "example.com", "--ports", "--no-save"])
    assert scanned == []


# ----------------------------------------------------------- project layout --
def test_my_own_files_exist_and_init_files_are_empty():
    for name in ["exposureiq/__init__.py", "exposureiq/__main__.py", "exposureiq/cli.py", "exposureiq/output.py",
                 "exposureiq/demo_data.py", "exposureiq/discovery/__init__.py", "exposureiq/discovery/subdomains.py",
                 "requirements.txt", ".gitignore", "pyproject.toml"]:
        assert (ROOT / name).is_file(), f"missing {name}"
    assert (ROOT / "exposureiq/__init__.py").stat().st_size == 0
    assert (ROOT / "exposureiq/discovery/__init__.py").stat().st_size == 0


@pytest.mark.parametrize("args", [["--help"], ["scan", "--help"]])
def test_help_commands_work_with_python_m(args):
    result = subprocess.run([sys.executable, "-m", "exposureiq", *args], cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0 and "usage:" in result.stdout
