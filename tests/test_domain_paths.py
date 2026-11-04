"""Domain folders, explicit paths, and non-destructive legacy scan discovery."""

import socket
from pathlib import Path

import pytest

from exposureiq import cli, storage
from exposureiq.diffing import pipeline
from exposureiq.paths import domain_directory, saved_json_paths, scan_output_path
from exposureiq.report.render import generate_report
from exposureiq.tui.control import ScanControl
from exposureiq.tui.saved import list_saved
from exposureiq.tui.scan import run_scan


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    def blocked(*args, **kwargs):
        raise AssertionError("Path and export tests must stay offline")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(pipeline.noise, "load_ignore_rules", lambda: [])


def saved(root, name, *, domain="example.com", day=1):
    scan = storage.build_scan(domain, [], started_at=f"2026-10-{day:02d}T10:00:00Z")
    scan["scan_id"] = f"SCAN-{domain}-{day}"
    path = root / name
    storage.save_scan(scan, str(path))
    return scan, path


def test_new_default_paths_are_separate_domain_folders():
    assert scan_output_path("example.com", "scan.json") == Path("results/example.com/scan.json")
    assert scan_output_path("example.net", "scan.json") == Path("results/example.net/scan.json")
    assert domain_directory("report", "https://Example.COM/path") == Path("report/example.com")


def test_custom_roots_and_explicit_json_filenames():
    assert scan_output_path("example.com", "scan.json", "custom/") == Path("custom/example.com/scan.json")
    assert scan_output_path("example.com", "unused.json", "exact.json") == Path("exact.json")
    assert scan_output_path("example.com", "unused.json", "exact.JSON") == Path("exact.JSON")
    assert domain_directory("report/example.com", "example.com") == Path("report/example.com")
    assert scan_output_path("example.com", "scan.json", "results/example.com") == Path("results/example.com/scan.json")


@pytest.mark.parametrize("output", [None, "custom/"])
def test_passive_scan_saves_two_domains_in_separate_folders(tmp_path, monkeypatch, output):
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", lambda domain, **kwargs: {
        "subfinder": [f"www.{domain}"], "crtsh": [],
    })
    monkeypatch.setattr(cli, "resolve_hosts", lambda hosts, **kwargs: [
        {"host": host, "ips": ["192.0.2.10"]} for host in hosts
    ])
    saved_paths = []
    for domain in ("example.com", "example.net"):
        flags = ["scan", domain, "--passive", "--no-report"]
        if output:
            flags += ["-o", output]
        args = cli.build_parser().parse_args(flags)
        result = run_scan(args, cli._stages(), lambda event: None, ScanControl())
        assert result["return_code"] == 0
        path = Path(result["saved_to"])
        assert path.parent == Path(output or "results") / domain
        assert storage.load_scan(str(path))["target"] == domain
        saved_paths.append(path)
    assert len(list_saved(output or "results")) == 2
    assert all(path.exists() for path in saved_paths)
    assert not list(Path(output or "results").glob("*.json"))


@pytest.mark.parametrize("domain", ["../../", "", "not a domain", "example..com"])
def test_invalid_domain_cannot_escape_the_output_root(domain):
    with pytest.raises(ValueError):
        domain_directory("report", domain)
    assert not Path("report").exists()


def test_domain_lookup_reads_nested_and_legacy_files_without_moving_anything(tmp_path):
    root = tmp_path / "results"
    old, old_path = saved(root, "legacy.json", day=1)
    new, new_path = saved(root / "example.com", "new.json", day=2)
    _, other = saved(root / "example.net", "other.json", domain="example.net", day=3)
    _, misplaced = saved(root / "example.com", "misplaced.json", domain="example.net", day=4)
    broken = root / "example.com" / "broken.json"
    broken.write_text("{invalid", encoding="utf-8")
    originals = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                 for path in (old_path, new_path, other, misplaced, broken)}
    for directory in (root, root / "example.com"):
        entries = pipeline.find_domain_scans("example.com", directory)
        assert [entry["scan"] for entry in entries] == [old, new]
        assert pipeline.find_scan_history(new, directory) == [old, new]
        assert pipeline.diff_domain("example.com", directory)["old"]["scan_id"] == old["scan_id"]
    assert all((path.read_bytes(), path.stat().st_mtime_ns) == value for path, value in originals.items())


def test_saved_browser_lists_domain_relative_names_and_broken_files(tmp_path):
    root = tmp_path / "results"
    _, flat = saved(root, "legacy.json")
    _, nested = saved(root / "example.com", "scan.json", day=2)
    _, other = saved(root / "example.net", "scan.json", domain="example.net", day=3)
    broken = root / "example.com" / "broken.json"
    broken.write_text("{invalid", encoding="utf-8")
    entries = list_saved(root)
    assert {entry["name"] for entry in entries} == {
        "legacy.json", "example.com/scan.json", "example.net/scan.json", "example.com/broken.json",
    }
    assert {entry["path"] for entry in entries} == {str(path) for path in (flat, nested, other, broken)}
    assert next(entry for entry in entries if entry["name"].endswith("broken.json"))["error"]
    assert len(list_saved(root / "example.com")) == 2


def test_domain_lookup_does_not_walk_unrelated_or_arbitrarily_deep_folders(tmp_path):
    root = tmp_path / "results"
    scan, direct = saved(root / "example.com", "scan.json")
    saved(root / "example.net", "wrong-folder.json", day=2)
    saved(root / "example.com" / "nested", "deep.json", day=3)
    assert [entry["scan"] for entry in pipeline.find_domain_scans("example.com", root)] == [scan]
    assert saved_json_paths(root, "example.com") == [direct]


def test_exports_group_by_domain_and_update_the_same_index_only(tmp_path):
    root = tmp_path / "results"
    _, first = saved(root / "example.com", "first.json", day=1)
    _, second = saved(root / "example.com", "second.json", day=2)
    _, other = saved(root / "example.net", "other.json", domain="example.net", day=3)
    original = {path: path.read_bytes() for path in (first, second, other)}
    pdf = generate_report(str(first), format="pdf", results_dir=root)
    pdf_bytes = Path(pdf["pdf"]).read_bytes()
    first_export = generate_report(str(first), format="html", results_dir=root)
    second_export = generate_report(str(second), format="html", results_dir=root)
    assert first_export["html"] == second_export["html"] == "report/example.com/index.html"
    assert len(second_export["domain"]["reports"]) == 2
    assert "example.net" not in Path(second_export["html"]).read_text(encoding="utf-8")
    assert Path(pdf["pdf"]).parent == Path("report/example.com")
    assert Path(pdf["pdf"]).read_bytes() == pdf_bytes
    assert all(path.read_bytes() == value for path, value in original.items())
    assert not list(Path("report").glob("*.html"))
    assert not Path("report/example.net").exists()


def test_explicit_report_filename_and_existing_domain_output_directory_stay_exact(tmp_path):
    root = tmp_path / "results"
    _, source = saved(root / "example.com", "scan.json")
    explicit = generate_report(str(source), output=str(tmp_path / "chosen.html"), results_dir=root)
    assert explicit["html"] == str(tmp_path / "chosen.html")
    grouped = generate_report(str(source), output="report/example.com", format="both", results_dir=root)
    assert grouped["html"] == "report/example.com/index.html"
    assert Path(grouped["pdf"]).parent == Path("report/example.com")
    assert not Path("report/example.com/example.com").exists()
