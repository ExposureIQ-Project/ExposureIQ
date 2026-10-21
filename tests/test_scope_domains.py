"""A domain entry authorizes its subdomains; scans use that to pick active mode.

Fake stages only: no Subfinder, Nmap, DNS, HTTP or TLS. The repository scope
file is a temporary fake, so the developer's real scope.txt is never read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from exposureiq import cli, storage
from exposureiq.discovery import scope
from exposureiq.tui.control import ScanControl
from exposureiq.tui.scan import ScanStages, run_scan


@pytest.fixture
def repo_scope(monkeypatch, tmp_path):
    path = tmp_path / "repo" / "scope.txt"
    path.parent.mkdir()
    monkeypatch.setattr(scope, "SCOPE_FILE", path)
    return path


def write_scope(path: Path, *lines: str) -> None:
    path.write_text("# fake repository scope\n" + "\n".join(lines) + "\n", encoding="utf-8")


def test_domain_entry_authorizes_its_subdomains_only(repo_scope):
    write_scope(repo_scope, "example.com")

    for allowed in ("example.com", "api.example.com", "deep.api.example.com", "EXAMPLE.COM."):
        assert scope.is_in_scope(allowed) is True
    for denied in ("notexample.com", "example.com.evil.net", "example.net", "192.0.2.10", "2001:db8::1"):
        assert scope.is_in_scope(denied) is False


def test_exact_ip_and_cidr_entries_still_work(repo_scope):
    write_scope(repo_scope, "192.0.2.10", "198.51.100.0/24")

    assert scope.is_in_scope("192.0.2.10") is True
    assert scope.is_in_scope("198.51.100.25") is True
    assert scope.is_in_scope("203.0.113.25") is False
    assert scope.is_in_scope("api.192.0.2.10") is False


def test_wildcard_and_invalid_entries_do_not_authorize_a_subtree(repo_scope):
    write_scope(repo_scope, "*.example.com", "bad_domain.example", "com")

    for target in ("api.example.com", "x.bad_domain.example", "example.com"):
        assert scope.is_in_scope(target) is False


def test_user_scope_domain_also_covers_subdomains(repo_scope, isolated_user_scope):
    write_scope(repo_scope, "repo.example.net")
    isolated_user_scope.parent.mkdir(parents=True)
    isolated_user_scope.write_text("example.com\n", encoding="utf-8")

    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("api.repo.example.net") is True
    assert scope.is_in_scope("api.example.org") is False


class Recorder:
    def __init__(self, resolver):
        self.checks_calls = []
        self.ports_calls = []

        def fake_find(domain, **kwargs):
            return {"fake": ["api.example.com", "www.example.com"]}

        def fake_checks(assets):
            self.checks_calls.extend(asset["host"] for asset in assets)
            for asset in assets:
                asset["technologies"] = []
                asset["findings"] = []
            return assets

        def fake_ports(host):
            self.ports_calls.append(host)
            return [{"port": 443, "protocol": "tcp", "service": "https"}]

        self.stages = ScanStages(
            fake_find, resolver, storage.build_scan, storage.save_scan,
            lambda: scope.is_in_scope, lambda: fake_checks,
            lambda: (fake_ports, scope.is_in_scope), lambda: True,
            lambda target: False,
        )


def run(args, stages, events=None):
    reporter = events.append if events is not None else (lambda event: None)
    return run_scan(args, stages, reporter, ScanControl())


def args_for(tmp_path: Path, *extra: str):
    args = cli.build_parser().parse_args(["scan", "example.com", *extra])
    args.output = str(tmp_path / "scan.json")
    return args


def test_domain_in_scope_runs_checks_and_ports_for_subdomains(repo_scope, tmp_path):
    write_scope(repo_scope, "example.com")
    recorder = Recorder(lambda hosts: [{"host": host, "ips": ["192.0.2.10"]} for host in hosts])

    result = run(args_for(tmp_path), recorder.stages)

    assert recorder.checks_calls == ["example.com", "api.example.com", "www.example.com"]
    # All three share one IP, so the authorized name is scanned once.
    assert recorder.ports_calls == ["example.com"]
    assert result["mode"] == "full"
    assert result["skipped_hosts"] == [] and result["skipped_scope_ips"] == []
    assert result["port_rows"] == [("192.0.2.10", [{"port": 443, "protocol": "tcp", "service": "https"}])]
    saved = storage.load_scan(str(tmp_path / "scan.json"))
    assert [asset["ips"][0]["open_ports"] for asset in saved["assets"]] == [
        [{"port": 443, "protocol": "tcp", "service": "https"}],
    ] * 3


def test_domain_not_in_scope_is_passive_discovery_only(repo_scope, tmp_path):
    write_scope(repo_scope, "# nothing authorized")
    recorder = Recorder(lambda hosts: [{"host": host, "ips": ["192.0.2.20"]} for host in hosts])

    result = run(args_for(tmp_path), recorder.stages)

    assert recorder.checks_calls == [] and recorder.ports_calls == []
    assert result["mode"] == "passive"
    assert result["names"] == ["api.example.com", "www.example.com"]
    assert result["skipped_hosts"] == ["example.com", "api.example.com", "www.example.com"]
    assert result["phase_states"]["Web checks"] == "skipped"
    assert result["phase_states"]["Ports"] == "skipped"
    assert result["phase_counts"]["Scope"] == 0
    saved = storage.load_scan(str(tmp_path / "scan.json"))
    assert all(asset["ips"][0]["open_ports"] == [] for asset in saved["assets"])


def test_specific_authorized_host_still_works_without_apex(repo_scope, tmp_path):
    write_scope(repo_scope, "api.example.com")
    recorder = Recorder(lambda hosts: [{"host": host, "ips": ["192.0.2.30"]} for host in hosts])

    result = run(args_for(tmp_path), recorder.stages)

    assert recorder.checks_calls == ["api.example.com"]
    assert recorder.ports_calls == ["api.example.com"]
    assert result["mode"] == "partial"
    assert result["skipped_hosts"] == ["example.com", "www.example.com"]


def test_multi_ipv4_host_is_not_guessed(repo_scope, tmp_path):
    write_scope(repo_scope, "example.com")
    recorder = Recorder(lambda hosts: [
        {"host": host, "ips": ["192.0.2.40", "192.0.2.41"]} for host in hosts])

    events = []
    result = run(args_for(tmp_path), recorder.stages, events)

    assert recorder.ports_calls == []
    assert result["port_rows"] == []
    assert any("2 IPv4 addresses; ports skipped" in event.get("message", "") for event in events)


def test_passive_flag_never_loads_active_stages(repo_scope, tmp_path):
    write_scope(repo_scope, "example.com")

    def blocked():
        raise AssertionError("active stage loaded during --passive")

    recorder = Recorder(lambda hosts: [])
    recorder.stages.load_checks = blocked
    recorder.stages.load_ports = blocked
    result = run(args_for(tmp_path, "--passive"), recorder.stages)

    assert result["mode"] == "passive"
    assert result["phase_states"]["Web checks"] == "skipped"
    assert result["phase_states"]["Ports"] == "skipped"
