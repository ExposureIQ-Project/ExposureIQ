"""Tests for the command line (exposureiq scan ...). Everything outside is faked:
no internet, no Subfinder, no DNS and no Nmap are needed.

Run from the project root:   python -m pytest
"""
import json

import pytest

from exposureiq import cli


def fake_sources(names, crtsh=()):
    def find(domain, **kwargs):
        return {"subfinder": list(names), "crtsh": list(crtsh)}
    return find


def fake_resolver(live=None):
    """Resolve every name to a fake IP, except names listed in `dead`."""
    def resolve(hosts, **kwargs):
        return [{"host": h, "ips": [f"203.0.113.{i + 1}"]} for i, h in enumerate(hosts)
                if live is None or h in live]
    return resolve


class Recorder:
    """Stands in for build_scan/save_scan and remembers what it was given."""
    def __init__(self):
        self.scan = self.path = None

    def build(self, target, assets, started_at=None):
        return {"target": target, "assets": assets, "started_at": started_at}

    def save(self, scan, path):
        self.scan, self.path = scan, path


@pytest.fixture
def stages(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", fake_sources(["api.example.com", "www.example.com"]))
    monkeypatch.setattr(cli, "resolve_hosts", fake_resolver())
    monkeypatch.setattr(cli, "build_scan", rec.build)
    monkeypatch.setattr(cli, "save_scan", rec.save)
    return rec


def run(*argv):
    return cli.main(["scan", *argv])


def read(capsys):
    """Everything printed so far, with line breaks and extra spaces removed (long messages wrap)."""
    return " ".join(capsys.readouterr().out.split())


# ----------------------------------------------------------- the happy path --
def test_full_run_prints_subdomains_ips_and_saves(stages, capsys, tmp_path):
    out_file = tmp_path / "out.json"
    assert run("example.com", "-o", str(out_file)) == 0
    text = read(capsys)
    assert "api.example.com" in text and "www.example.com" in text    # subdomains table
    assert "203.0.113.1" in text                                      # IP table
    assert "Saved 3 hosts" in text
    # A long path (Windows temp folders) can be cut in the middle when it wraps,
    # so compare it with all whitespace removed.
    assert "".join(str(out_file).split()) in "".join(text.split())
    assert stages.path == str(out_file)


def test_json_structure_matches_the_findings_format(stages, tmp_path):
    run("example.com", "-o", str(tmp_path / "x.json"))
    scan = stages.scan
    assert scan["target"] == "example.com"
    assert scan["started_at"].endswith("Z")                           # real start time is passed on
    assert scan["assets"][0] == {"host": "example.com",               # the domain itself comes first
                                 "ips": [{"ip": "203.0.113.1", "open_ports": []}]}
    assert [a["host"] for a in scan["assets"]] == ["example.com", "api.example.com", "www.example.com"]


def test_default_file_goes_to_results_folder(stages, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run("example.com")
    assert stages.path.replace("\\", "/").startswith("results/example.com_")
    assert stages.path.endswith(".json")


def test_no_apex_leaves_the_domain_itself_out(stages):
    run("example.com", "--no-apex", "--no-save")
    # nothing saved, but the lookup must not have included the apex
    assert stages.scan is None


def test_apex_is_looked_up_by_default(monkeypatch, stages):
    seen = []
    monkeypatch.setattr(cli, "resolve_hosts", lambda hosts, **k: seen.append(list(hosts)) or [])
    run("example.com", "--no-save")
    assert seen == [["example.com", "api.example.com", "www.example.com"]]
    seen.clear()
    run("example.com", "--no-save", "--no-apex")
    assert seen == [["api.example.com", "www.example.com"]]


def test_no_save_writes_nothing(stages, capsys):
    assert run("example.com", "--no-save") == 0
    assert stages.path is None
    assert "Not saved" in read(capsys)


def test_dead_names_are_counted(monkeypatch, stages, capsys):
    monkeypatch.setattr(cli, "resolve_hosts", fake_resolver(live={"example.com", "api.example.com"}))
    run("example.com", "--no-save")
    text = read(capsys)
    assert "1 had no DNS answer" in text


def test_table_is_limited_unless_all(monkeypatch, stages, capsys):
    names = [f"h{i:03}.example.com" for i in range(100)]
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", fake_sources(names))
    run("example.com", "--no-save", "--limit", "10")
    text = read(capsys)
    assert "h009.example.com" in text and "h010.example.com" not in text
    assert "and 90 more" in text
    run("example.com", "--no-save", "--all")
    assert "h099.example.com" in read(capsys)


def test_no_subdomains_still_looks_up_the_domain(monkeypatch, stages, capsys):
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", fake_sources([]))
    assert run("example.com", "--no-save") == 0
    out = read(capsys)
    assert "No subdomains found" in out and "example.com" in out


# ------------------------------------------------------------------- errors --
def test_invalid_domain_is_a_clean_error(capsys):
    assert run("not a domain") == 2
    assert "does not look like a valid domain" in read(capsys)


def test_save_error_is_reported(monkeypatch, stages, capsys):
    def boom(scan, path):
        raise OSError("disk full")
    monkeypatch.setattr(cli, "save_scan", boom)
    assert run("example.com") == 1
    assert "Could not save" in read(capsys)


def test_no_command_shows_help(capsys):
    assert cli.main([]) == 2
    assert "scan" in read(capsys)


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert "exposureiq" in read(capsys)


# ------------------------------------- parts that teammates have not merged yet --
def test_works_before_dns_resolver_is_merged(monkeypatch, stages, capsys):
    monkeypatch.setattr(cli, "resolve_hosts", None)
    assert run("example.com") == 0
    out = read(capsys)
    assert "api.example.com" in out                  # step 1 still works
    assert "dns_resolver.py is missing" in out
    assert "Nothing to save yet" in out
    assert stages.path is None


def test_works_before_storage_is_merged(monkeypatch, stages, capsys):
    monkeypatch.setattr(cli, "build_scan", None)
    monkeypatch.setattr(cli, "save_scan", None)
    assert run("example.com") == 0
    out = read(capsys)
    assert "203.0.113.1" in out                      # step 2 still works
    assert "storage.py is missing" in out


# ------------------------------------------------------------------- --ports --
def test_ports_only_scans_in_scope_ipv4(monkeypatch, stages, capsys):
    scanned = []

    def scan_ports(ip):
        scanned.append(ip)
        return [{"port": 443, "protocol": "tcp", "service": "https"}]

    monkeypatch.setattr(cli, "_load_ports", lambda: (scan_ports, lambda ip: ip == "203.0.113.2"))
    monkeypatch.setattr(cli, "resolve_hosts", lambda hosts, **k: [
        {"host": "example.com", "ips": ["203.0.113.1"]},
        {"host": "api.example.com", "ips": ["203.0.113.2", "2001:db8::2"]},
    ])
    assert run("example.com", "--ports") == 0
    assert scanned == ["203.0.113.2"]                          # others are skipped, never scanned
    assert "Skipped 2 IP address" in read(capsys)
    api = next(a for a in stages.scan["assets"] if a["host"] == "api.example.com")
    by_ip = {entry["ip"]: entry["open_ports"] for entry in api["ips"]}
    assert by_ip["203.0.113.2"] == [{"port": 443, "protocol": "tcp", "service": "https"}]
    assert by_ip["2001:db8::2"] == []


def test_ports_failure_does_not_stop_the_scan(monkeypatch, stages, capsys):
    def scan_ports(ip):
        raise RuntimeError("Nmap was not found")
    monkeypatch.setattr(cli, "_load_ports", lambda: (scan_ports, lambda ip: True))
    assert run("example.com", "--ports") == 0
    assert "Nmap was not found" in read(capsys)
    assert stages.scan is not None                              # results are still saved


def test_ports_not_merged_yet(monkeypatch, stages, capsys):
    monkeypatch.setattr(cli, "_load_ports", lambda: (None, None))
    assert run("example.com", "--ports") == 0
    assert "Port scanning is not available yet" in read(capsys)


# ------------------------------------ with the real storage module (if merged) --
def test_real_storage_round_trip(monkeypatch, tmp_path):
    storage = pytest.importorskip("exposureiq.storage")
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", fake_sources(["api.example.com"]))
    monkeypatch.setattr(cli, "resolve_hosts", fake_resolver())
    monkeypatch.setattr(cli, "build_scan", storage.build_scan)
    monkeypatch.setattr(cli, "save_scan", storage.save_scan)
    path = tmp_path / "scan.json"
    assert run("example.com", "-o", str(path)) == 0
    scan = storage.load_scan(str(path))                         # valid according to the findings format
    assert scan["target"] == "example.com"
    assert [a["host"] for a in scan["assets"]] == ["example.com", "api.example.com"]
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == storage.SCHEMA_VERSION
