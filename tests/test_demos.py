"""The ten-scan demo is deterministic, schema-valid, and completely offline."""

import ipaddress
import json
import socket
from pathlib import Path

import pytest

from exposureiq import cli, storage
from exposureiq.demo_data import DEMO_STORY, build_demo_scans, demo_assets
from exposureiq.fingerprint.severity import RULES
from exposureiq.tui.control import ScanCancelled, ScanControl
from exposureiq.tui.scan import run_scan


@pytest.fixture(autouse=True)
def offline_demo(monkeypatch, tmp_path):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("--demos must not call network or real scan stages")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", blocked)
    monkeypatch.setattr(cli, "resolve_hosts", blocked)
    monkeypatch.setattr(cli, "_load_scope", blocked)
    monkeypatch.setattr(cli, "_load_checks", blocked)
    monkeypatch.setattr(cli, "_load_ports", blocked)
    monkeypatch.setattr(cli.shutil, "which", blocked)
    yield
    assert attempts == []


def findings(scan):
    return [finding for asset in scan["assets"] for finding in asset["findings"]]


def test_demo_story_is_repeatable_with_ten_distinct_snapshots(tmp_path):
    scans = build_demo_scans()
    assert len(scans) == len(DEMO_STORY) == 10
    assert scans == build_demo_scans()
    assert [scan["scan_id"] for scan in scans] == [f"DEMO-HISTORY-{number:02d}" for number in range(1, 11)]
    assert len({json.dumps(scan["assets"], sort_keys=True) for scan in scans}) == 10
    assert [scan["started_at"] for scan in scans] == sorted(scan["started_at"] for scan in scans)
    for number, scan in enumerate(scans, 1):
        path = tmp_path / f"fixture-{number}.json"
        storage.save_scan(scan, str(path))
        assert storage.load_scan(str(path)) == scan
    scans[0]["assets"][0]["ips"][0]["open_ports"].clear()
    assert build_demo_scans()[0]["assets"][0]["ips"][0]["open_ports"]
    assert scans[1]["assets"][0]["ips"][0]["open_ports"]


def test_severity_grows_at_scans_three_and_four_then_recovers():
    scans = build_demo_scans()
    high = [sum(finding["severity"] == "high" for finding in findings(scan)) for scan in scans]
    total = [len(findings(scan)) for scan in scans]
    assert high == [0, 0, 5, 11, 7, 1, 0, 0, 0, 0]
    assert total[0] < total[1] < total[2] < total[3]
    assert total[3:] == sorted(total[3:], reverse=True)
    assert {finding["severity"] for finding in findings(scans[3])} == {"high", "medium", "low"}
    assert len(findings(scans[-1])) == 1
    assert findings(scans[-1])[0]["severity"] == "low"
    assert all(port["port"] == 443 for asset in scans[-1]["assets"]
               for entry in asset["ips"] for port in entry["open_ports"])


def test_demo_evidence_uses_real_rules_and_documentation_addresses():
    networks = [ipaddress.ip_network(prefix) for prefix in
                ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for scan in build_demo_scans():
        ids = []
        for asset in scan["assets"]:
            assert asset["host"] == "example.com" or asset["host"].endswith(".example.com")
            ports = {(entry["ip"], port["port"]) for entry in asset["ips"] for port in entry["open_ports"]}
            assert all(any(ipaddress.ip_address(entry["ip"]) in network for network in networks)
                       for entry in asset["ips"])
            for finding in asset["findings"]:
                rule = RULES[finding["rule"]]
                assert finding["severity"] == rule["severity"]
                assert finding["title"] == "DEMO: " + rule["title"]
                assert finding["recommendation"] == rule["recommendation"]
                assert finding["detail"].startswith("DEMO: ")
                if finding["rule"].startswith("ports."):
                    assert (finding["ip"], finding["port"]) in ports
                    assert "No authentication, data access or exploitation was attempted" in finding["detail"]
                ids.append(finding["id"])
        assert ids == [f"F-{number:04d}" for number in range(1, len(ids) + 1)]


@pytest.mark.parametrize("number", [0, 11, -1, True, "3", None])
def test_demo_assets_reject_invalid_scan_numbers(number):
    with pytest.raises(ValueError, match="1 to 10"):
        demo_assets(number)


def test_demos_cli_saves_ten_files_and_ignores_the_real_domain(tmp_path, capsys):
    assert cli.main(["scan", "real.example.net", "--demos", "--plain", "--no-report"]) == 0
    paths = sorted((tmp_path / "results" / "example.com").glob("*.json"))
    assert [path.name for path in paths] == [f"demo_history_{number:02d}.json" for number in range(1, 11)]
    assert [storage.load_scan(str(path)) for path in paths] == build_demo_scans()
    assert not (tmp_path / "report").exists()
    text = capsys.readouterr().out
    assert "DEMO scan 03/10" in text and "DEMO scan 10/10" in text
    assert "No network" in text


def test_demos_keeps_an_automatic_pdf_for_each_saved_scan(tmp_path):
    assert cli.main(["scan", "example.com", "--demos", "--plain"]) == 0
    pdfs = sorted((tmp_path / "report" / "example.com").glob("*.pdf"))
    assert len(pdfs) == 10
    assert not list((tmp_path / "report").rglob("*.html"))
    assert not list((tmp_path / "report").rglob("*.docx"))
    for number, path in enumerate(pdfs, 1):
        data = path.read_bytes()
        assert data.startswith(b"%PDF-1.4")
        assert b"simulated" in data and b"No network" in data
        assert f"DEMO-HISTORY-{number:02d}".encode() in data
        for future in range(number + 1, 11):
            assert f"DEMO-HISTORY-{future:02d}".encode() not in data
        if number > 1:
            assert b"scan-by-scan history" in data.lower() and b"DEMO-HISTORY-01" in data


@pytest.mark.parametrize("output, pattern", [
    ("samples", "samples/example.com/demo_history_*.json"),
    ("samples/", "samples/example.com/demo_history_*.json"),
    ("story.json", "story_*.json"),
    ("story.JSON", "story_*.JSON"),
])
def test_demos_output_directory_or_numbered_json_name(tmp_path, output, pattern):
    assert cli.main(["scan", "example.com", "--demos", "--plain", "--no-report", "-o", output]) == 0
    assert len(list(tmp_path.glob(pattern))) == 10
    assert not (tmp_path / "results").exists()


def test_no_save_creates_no_files_or_reports(tmp_path, capsys):
    assert cli.main(["scan", "example.com", "--demos", "--plain", "--no-save"]) == 0
    assert not (tmp_path / "results").exists() and not (tmp_path / "report").exists()
    assert "DEMO scan 10/10" in capsys.readouterr().out


def test_passive_and_no_apex_options_still_work(tmp_path):
    assert cli.main(["scan", "example.com", "--demos", "--plain", "--passive", "--no-apex", "--no-report"]) == 0
    paths = list((tmp_path / "results" / "example.com").glob("*.json"))
    assert len(paths) == 10
    for path in paths:
        scan = storage.load_scan(str(path))
        assert all(asset["host"] != "example.com" and not asset["findings"] and not asset["technologies"]
                   and all(not entry["open_ports"] for entry in asset["ips"]) for asset in scan["assets"])


def test_demo_flags_are_mutually_exclusive(tmp_path):
    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "example.com", "--demo", "--demos", "--plain"])
    assert error.value.code == 2
    assert not (tmp_path / "results").exists()


def test_repeat_demos_reuses_identical_json_without_modifying_it(tmp_path):
    args = ["scan", "example.com", "--demos", "--plain", "--no-report"]
    assert cli.main(args) == 0
    paths = sorted((tmp_path / "results" / "example.com").glob("*.json"))
    before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
    assert cli.main(args) == 0
    assert [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths] == before


def test_conflicting_output_is_rejected_before_any_demo_files_are_written(tmp_path, capsys):
    path = tmp_path / "results" / "example.com" / "demo_history_06.json"
    unrelated = storage.build_scan("example.com", [], started_at="2026-10-06T10:00:00Z")
    storage.save_scan(unrelated, str(path))
    before = path.read_bytes()
    assert cli.main(["scan", "example.com", "--demos", "--plain"]) == 1
    assert path.read_bytes() == before
    assert list(path.parent.glob("*.json")) == [path]
    assert not (tmp_path / "report").exists()
    assert "different data" in " ".join(capsys.readouterr().out.split())


def test_partial_save_failure_keeps_existing_files_but_disables_last_scan_export(tmp_path, monkeypatch):
    def fail_on_five(scan, path):
        if scan["scan_id"] == "DEMO-HISTORY-05":
            raise OSError("Disk is full")
        storage.save_scan(scan, path)

    monkeypatch.setattr(cli, "save_scan", fail_on_five)
    args = cli.build_parser().parse_args(["scan", "example.com", "--demos", "--no-report"])
    result = run_scan(args, cli._stages(), lambda event: None, ScanControl())
    assert result["return_code"] == 1 and result["saved_to"] is None
    assert len(result["saved_scans"]) == 4
    assert len(list((tmp_path / "results" / "example.com").glob("*.json"))) == 4


def test_cancelled_history_never_starts_saving(tmp_path):
    control = ScanControl()
    control.cancel()
    args = cli.build_parser().parse_args(["scan", "example.com", "--demos"])
    with pytest.raises(ScanCancelled):
        run_scan(args, cli._stages(), lambda event: None, control)
    assert not (tmp_path / "results").exists() and not (tmp_path / "report").exists()


def test_pdf_failure_does_not_stop_the_remaining_demo_snapshots(tmp_path, monkeypatch):
    def broken_report(*args):
        raise OSError("Report destination is read-only")

    monkeypatch.setattr(cli, "_auto_report", broken_report)
    args = cli.build_parser().parse_args(["scan", "example.com", "--demos"])
    result = run_scan(args, cli._stages(), lambda event: None, ScanControl())
    assert result["return_code"] == 0 and len(result["saved_scans"]) == 10
    assert result["report_to"] is None
    assert len(result["warnings"]) == 10
    assert Path(result["saved_to"]).name == "demo_history_10.json"
