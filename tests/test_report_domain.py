"""Offline domain dashboards, exact scan selection, links and safe embedded code."""

import base64
import copy
import hashlib
import json
import os
import socket
from pathlib import Path

import pytest

from exposureiq import storage
from exposureiq.demo_data import build_demo_scans
from exposureiq.diffing import pipeline
from exposureiq.report.interactive import SCRIPT
from exposureiq.report.render import generate_report

FIXED_TIME = "2026-11-04T12:00:00Z"


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("Domain dashboards must only read saved data")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(pipeline.noise, "load_ignore_rules", lambda: [])
    yield
    assert attempts == []


def saved_story(root):
    scans, paths = build_demo_scans(), []
    for number, scan in enumerate(scans, 1):
        path = root / "example.com" / f"scan_{number:02d}.json"
        storage.save_scan(scan, str(path))
        paths.append(path)
    return scans, paths


@pytest.mark.parametrize("number", [1, 3, 5, 10])
def test_domain_home_lists_all_scans_newest_first_and_each_view_stops_at_its_scan(tmp_path, number, portal_html):
    root = tmp_path / "results"
    scans, paths = saved_story(root)
    original = [path.read_bytes() for path in paths]
    result = generate_report(str(paths[number - 1]), format="html", results_dir=root, generated_at=FIXED_TIME)
    page = Path(result["html"]).read_text(encoding="utf-8")
    parsed = portal_html(page)
    assert [card["data-scan-card"] for card in parsed.cards] == [scan["scan_id"] for scan in reversed(scans)]
    assert len(parsed.views) == len(result["domain"]["reports"]) == 10
    assert len(result["report"]["history"]) == number
    for index, (scan, report) in enumerate(zip(scans, result["domain"]["reports"]), 1):
        view = parsed.views[(scan["scan_id"], scan["started_at"])]
        assert all(item["scan_id"] in view for item in scans[:index])
        assert all(item["scan_id"] not in view for item in scans[index:])
        assert [point["scan_id"] for point in report["history"]] == [item["scan_id"] for item in scans[:index]]
    assert len(parsed.ids) == len(set(parsed.ids))
    assert all(link.startswith("#") and link[1:] in parsed.ids for link in parsed.links)
    assert [path.read_bytes() for path in paths] == original


def test_each_chart_node_links_to_its_exact_dated_history_entry(tmp_path, portal_html):
    root = tmp_path / "results"
    _, paths = saved_story(root)
    result = generate_report(str(paths[2]), format="html", results_dir=root, generated_at=FIXED_TIME)
    parsed = portal_html(Path(result["html"]).read_text(encoding="utf-8"))
    assert parsed.points
    for point in parsed.points:
        entry = parsed.history[point["data-anchor"]]
        assert entry["data-history-scan"] == point["data-scan-id"]
        assert entry["data-history-time"] == point["data-scan-time"]
        assert point["href"] == "#" + entry["id"]
        assert point["data-scan-number"].isdigit()
        assert "UTC" in point["data-scan-date"]
        assert point["tabindex"] == "0" and point["role"] == "link"


def test_domain_home_and_charts_deduplicate_copied_files(tmp_path, portal_html):
    root = tmp_path / "results"
    scans, paths = saved_story(root)
    storage.save_scan(scans[1], str(root / "copied.json"))
    result = generate_report(str(paths[2]), format="html", results_dir=root)
    parsed = portal_html(Path(result["html"]).read_text(encoding="utf-8"))
    assert len(parsed.cards) == 10
    assert len(result["domain"]["groups"][0]["report"]["history"]) == 10


def test_scan_links_remain_stable_when_older_history_is_added(tmp_path, portal_html):
    root = tmp_path / "results"
    _, paths = saved_story(root)
    result = generate_report(str(paths[2]), format="html", results_dir=root)
    before = portal_html(Path(result["html"]).read_text(encoding="utf-8"))
    baseline = copy.deepcopy(build_demo_scans()[0])
    baseline.update(scan_id="DEMO-HISTORY-00", started_at="2026-09-30T12:00:00Z")
    storage.save_scan(baseline, str(root / "example.com" / "earlier.json"))
    result = generate_report(str(paths[2]), format="html", results_dir=root)
    after = portal_html(Path(result["html"]).read_text(encoding="utf-8"))
    old_links = {card["data-scan-card"]: card["href"] for card in before.cards}
    new_links = {card["data-scan-card"]: card["href"] for card in after.cards}
    assert all(new_links[key] == value for key, value in old_links.items())
    assert all(link[1:] in after.ids for link in after.links)


def test_domain_includes_real_and_demo_cards_but_keeps_their_trends_separate(tmp_path):
    root = tmp_path / "results"
    scans, paths = saved_story(root)
    real = copy.deepcopy(scans[0])
    real["scan_id"] = "REAL-01"
    storage.save_scan(real, str(root / "example.com" / "real.json"))
    one_off = copy.deepcopy(scans[0])
    one_off["scan_id"] = "DEMO-one-off"
    storage.save_scan(one_off, str(root / "example.com" / "one-off.json"))
    unrelated = storage.build_scan("example.net", [], started_at=FIXED_TIME)
    storage.save_scan(unrelated, str(root / "example.net" / "other.json"))
    result = generate_report(str(paths[2]), format="html", results_dir=root)
    domain = result["domain"]
    assert len(domain["reports"]) == 12
    groups = {group["key"]: group["report"] for group in domain["groups"]}
    assert set(groups) == {"real", "demo", "demo-history"}
    assert [point["scan_id"] for point in groups["real"]["history"]] == ["REAL-01"]
    assert [point["scan_id"] for point in groups["demo"]["history"]] == ["DEMO-one-off"]
    assert len(groups["demo-history"]["history"]) == 10
    assert "example.net" not in Path(result["html"]).read_text(encoding="utf-8")


def test_card_order_uses_saved_utc_time_not_file_modification_time(tmp_path, portal_html):
    root = tmp_path / "results"
    scans = [storage.build_scan("example.com", [], started_at=stamp) for stamp in (
        "2026-10-01T12:00:00+02:00", "2026-10-01T11:00:00Z", "2026-10-01T10:30:00-02:00",
    )]
    paths = []
    for number, scan in enumerate(scans, 1):
        scan["scan_id"] = f"SCAN-{number}"
        path = root / "example.com" / f"scan_{number}.json"
        storage.save_scan(scan, str(path))
        os.utime(path, (1000 - number, 1000 - number))
        paths.append(path)
    result = generate_report(str(paths[1]), format="html", results_dir=root)
    parsed = portal_html(Path(result["html"]).read_text(encoding="utf-8"))
    assert [card["data-scan-card"] for card in parsed.cards] == ["SCAN-3", "SCAN-2", "SCAN-1"]
    assert len(result["report"]["history"]) == 2


def test_explicit_baseline_only_changes_selected_view_not_home_history(tmp_path, portal_html):
    root = tmp_path / "results"
    scans, paths = saved_story(root)
    result = generate_report(str(paths[4]), compare=str(paths[2]), format="html", results_dir=root)
    assert result["diff"]["old"]["scan_id"] == scans[2]["scan_id"]
    assert len(result["domain"]["groups"][0]["report"]["diff"]["history"]) == 9
    parsed = portal_html(Path(result["html"]).read_text(encoding="utf-8"))
    assert all(link[1:] in parsed.ids for link in parsed.links)
    for point in parsed.points:
        assert parsed.history[point["data-anchor"]]["data-history-scan"] == point["data-scan-id"]


def test_disabled_comparison_keeps_scan_selection_and_valid_chart_targets(tmp_path, portal_html):
    root = tmp_path / "results"
    _, paths = saved_story(root)
    result = generate_report(str(paths[2]), format="html", include_diff=False, results_dir=root)
    assert all(report["diff"] is None for report in result["domain"]["reports"])
    page = Path(result["html"]).read_text(encoding="utf-8")
    parsed = portal_html(page)
    assert len(parsed.cards) == 10
    assert all(link[1:] in parsed.ids for link in parsed.links)
    assert "Run another scan" not in page


def test_only_the_fixed_hashed_script_can_run_and_untrusted_data_stays_text(tmp_path, portal_html):
    root = tmp_path / "results"
    scans, paths = saved_story(root)
    scan = scans[2]
    scan["scan_id"] = '</script><img src=x onerror="alert(1)">'
    finding = next(asset["findings"][0] for asset in scan["assets"] if asset["findings"])
    finding["title"] = '<svg onload="alert(2)"></svg>'
    storage.save_scan(scan, str(paths[2]))
    result = generate_report(str(paths[2]), format="html", results_dir=root,
                             title='</title><script>alert(3)</script>')
    page = Path(result["html"]).read_text(encoding="utf-8")
    parsed = portal_html(page)
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    assert parsed.scripts == [SCRIPT]
    assert f"script-src 'sha256-{digest}'" in page and "connect-src 'none'" in page
    assert "<img src=x" not in page and "<svg onload" not in page
    assert "&lt;svg onload" in page and "&lt;/script&gt;" in page
    assert "src=\"http" not in page and "href=\"http" not in page
    assert all(link[1:] in parsed.ids for link in parsed.links)


def test_domain_models_remain_json_serializable(tmp_path):
    root = tmp_path / "results"
    _, paths = saved_story(root)
    result = generate_report(str(paths[2]), format="html", results_dir=root)
    assert '"selected_scan_id": "DEMO-HISTORY-03"' in json.dumps(result["domain"])
