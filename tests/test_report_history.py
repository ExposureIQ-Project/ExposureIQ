"""One history window for offline CLI diffs and HTML/PDF/DOCX reports."""

import copy
import html
import json
import socket
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from docx import Document
from docx.oxml.ns import qn

from exposureiq import cli, storage
from exposureiq.demo_data import build_demo_scans
from exposureiq.diffing import pipeline
from exposureiq.report import branding
from exposureiq.report.docx import render_docx
from exposureiq.report.html import render_html
from exposureiq.report.model import build_report
from exposureiq.report.pdf import render_pdf
from exposureiq.report.render import generate_report

FIXED_TIME = "2026-11-04T12:00:00Z"


@pytest.fixture(autouse=True)
def no_network(monkeypatch, tmp_path):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("history and reporting must never send network traffic")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(pipeline.noise, "load_ignore_rules", lambda: [])
    yield
    assert attempts == []


def saved_story(tmp_path, *, real=False):
    directory = tmp_path / "results"
    scans = build_demo_scans()
    paths = []
    for number, scan in enumerate(scans, 1):
        if real:
            scan["scan_id"] = f"SCAN-{number:02d}"
        path = directory / f"scan_{number:02d}.json"
        storage.save_scan(scan, str(path))
        paths.append(path)
    return scans, paths


def docx_text(data):
    return "\n".join(element.text or "" for element in Document(BytesIO(data)).element.iter(qn("w:t")))


@pytest.mark.parametrize("fmt", ["html", "pdf", "docx"])
def test_no_diff_exports_explain_the_opt_out_instead_of_missing_history(tmp_path, fmt):
    _, paths = saved_story(tmp_path)
    result = generate_report(str(paths[4]), format=fmt, include_diff=False,
                             results_dir=tmp_path / "results", generated_at=FIXED_TIME)
    data = Path(result[fmt]).read_bytes()
    text = docx_text(data) if fmt == "docx" else data.decode("utf-8" if fmt == "html" else "latin-1")
    assert "Change comparisons were disabled" in text
    assert "Run another scan" not in text and "earlier saved scan" not in text
    assert result["report"]["comparison_enabled"] is False
    assert len(result["report"]["history"]) == 5


@pytest.mark.parametrize("fmt", ["html", "pdf", "docx"])
@pytest.mark.parametrize("number", [1, 3, 5, 10])
def test_all_formats_cover_baseline_through_selected_without_future_scans(tmp_path, fmt, number, portal_html):
    scans, paths = saved_story(tmp_path)
    originals = [path.read_bytes() for path in paths]
    result = generate_report(str(paths[number - 1]), results_dir=paths[0].parent,
                             format=fmt, output=str(tmp_path / "out"), generated_at=FIXED_TIME)
    report, diff = result["report"], result["diff"]
    assert report["scan_id"] == scans[number - 1]["scan_id"]
    assert [point["scan_id"] for point in report["history"]] == [scan["scan_id"] for scan in scans[:number]]
    assert report["severity"]["high"] == sum(finding["severity"] == "high" for asset in scans[number - 1]["assets"]
                                            for finding in asset["findings"])
    if number == 1:
        assert diff is None
    else:
        assert diff["old"]["scan_id"] == scans[0]["scan_id"]
        assert diff["new"]["scan_id"] == scans[number - 1]["scan_id"]
        assert len(diff["history"]) == number - 1
        assert [(step["old"]["scan_id"], step["new"]["scan_id"]) for step in diff["history"]] == [
            (scans[index - 1]["scan_id"], scans[index]["scan_id"]) for index in range(1, number)
        ]
    data = Path(result[fmt]).read_bytes()
    text = docx_text(data) if fmt == "docx" else data.decode("utf-8" if fmt == "html" else "latin-1")
    if fmt == "html":
        parsed = portal_html(text)
        assert len(parsed.cards) == 10
        text = parsed.views[(scans[number - 1]["scan_id"], scans[number - 1]["started_at"])]
    if number > 1:
        assert "scan-by-scan history" in text.lower()
        assert all(scan["scan_id"] in text for scan in scans[:number])
    assert all(scan["scan_id"] not in text for scan in scans[number:])
    assert "simulated" in text
    assert "hosts that were in scope" not in text
    if fmt == "html":
        assert branding.LOGO_SVG in text and "Findings over time" in text
    if fmt == "pdf":
        assert data.startswith(b"%PDF-1.4") and "FINDINGS OVER TIME" in text
    if fmt == "docx":
        with zipfile.ZipFile(BytesIO(data)) as archive:
            images = [archive.read(name) for name in archive.namelist() if name.startswith("word/media/")]
            assert images == [branding.logo_png()]
    assert [path.read_bytes() for path in paths] == originals


def test_later_snapshots_cannot_rewrite_an_earlier_report_model(tmp_path):
    scans = build_demo_scans()
    directory = tmp_path / "results"
    paths = []
    for number, scan in enumerate(scans[:3], 1):
        path = directory / f"scan_{number:02d}.json"
        storage.save_scan(scan, str(path))
        paths.append(path)
    before = generate_report(str(paths[-1]), results_dir=directory, format="pdf", generated_at=FIXED_TIME)
    before_pdf = Path(before["pdf"]).read_bytes()
    for number, scan in enumerate(scans[3:], 4):
        storage.save_scan(scan, str(directory / f"scan_{number:02d}.json"))
    after = generate_report(str(paths[-1]), results_dir=directory, format="pdf", generated_at=FIXED_TIME)
    assert before["report"] == after["report"]
    assert Path(after["pdf"]).read_bytes() == before_pdf


def test_real_history_uses_the_same_window_and_does_not_mix_demo_files(tmp_path):
    scans, paths = saved_story(tmp_path, real=True)
    for number, demo in enumerate(build_demo_scans(), 1):
        storage.save_scan(demo, str(paths[0].parent / f"demo_{number:02d}.json"))
    result = generate_report(str(paths[4]), results_dir=paths[0].parent, format="html", generated_at=FIXED_TIME)
    assert result["diff"]["old"]["scan_id"] == "SCAN-01"
    assert result["diff"]["new"]["scan_id"] == "SCAN-05"
    assert [point["scan_id"] for point in result["report"]["history"]] == [scan["scan_id"] for scan in scans[:5]]


def test_duplicate_files_do_not_count_as_extra_scans(tmp_path):
    scans, paths = saved_story(tmp_path)
    storage.save_scan(scans[1], str(paths[0].parent / "copied_scan.json"))
    result = generate_report(str(paths[2]), results_dir=paths[0].parent, format="html", generated_at=FIXED_TIME)
    assert len(result["report"]["history"]) == 3
    assert len(result["diff"]["history"]) == 2


def test_explicit_compare_limits_changes_but_charts_keep_earlier_history(tmp_path):
    scans, paths = saved_story(tmp_path)
    result = generate_report(str(paths[4]), compare=str(paths[2]), results_dir=paths[0].parent,
                             format="html", generated_at=FIXED_TIME)
    assert result["diff"]["old"]["scan_id"] == scans[2]["scan_id"]
    assert len(result["diff"]["history"]) == 2
    assert len(result["report"]["history"]) == 5
    assert "Compared with baseline scan DEMO-HISTORY-03" in " ".join(result["report"]["executive_summary"])


def test_compare_rejects_future_or_unrelated_demo_data(tmp_path):
    scans, paths = saved_story(tmp_path)
    with pytest.raises(ValueError, match="earlier scan"):
        generate_report(str(paths[2]), compare=str(paths[8]), results_dir=paths[0].parent)
    other = copy.deepcopy(scans[0])
    other["scan_id"] = "DEMO-one-off"
    old_path = paths[0].parent / "one_off_demo.json"
    storage.save_scan(other, str(old_path))
    with pytest.raises(ValueError, match="unrelated demos"):
        generate_report(str(paths[2]), compare=str(old_path), results_dir=paths[0].parent)


def test_no_diff_still_limits_charts_to_the_selected_scan(tmp_path):
    _, paths = saved_story(tmp_path)
    result = generate_report(str(paths[2]), include_diff=False, results_dir=paths[0].parent, format="html")
    assert result["diff"] is None
    assert len(result["report"]["history"]) == 3


def test_cli_single_scan_diff_stops_at_that_file(tmp_path, capsys):
    scans, paths = saved_story(tmp_path)
    assert cli.main(["diff", str(paths[2]), "--json"]) == 0
    diff = json.loads(capsys.readouterr().out)
    assert diff["old"]["scan_id"] == scans[0]["scan_id"]
    assert diff["new"]["scan_id"] == scans[2]["scan_id"]
    assert len(diff["history"]) == 2
    assert "DEMO-HISTORY-04" not in json.dumps(diff)


def test_cli_domain_diff_contains_all_ten_scans_in_json_and_plain_output(tmp_path, capsys):
    scans, _ = saved_story(tmp_path)
    assert cli.main(["diff", "example.com", "--json"]) == 0
    diff = json.loads(capsys.readouterr().out)
    assert diff["old"]["scan_id"] == scans[0]["scan_id"] and diff["new"]["scan_id"] == scans[-1]["scan_id"]
    assert len(diff["history"]) == 9
    assert cli.main(["diff", "example.com"]) == 0
    text = capsys.readouterr().out
    assert "Scan-by-scan history" in text and "DEMO-HISTORY-04" in text


def test_two_file_diff_keeps_explicit_baseline_and_intermediate_scans(tmp_path, capsys):
    scans, paths = saved_story(tmp_path)
    assert cli.main(["diff", str(paths[1]), str(paths[4]), "--json"]) == 0
    diff = json.loads(capsys.readouterr().out)
    assert diff["old"]["scan_id"] == scans[1]["scan_id"] and diff["new"]["scan_id"] == scans[4]["scan_id"]
    assert len(diff["history"]) == 3


def test_history_sorts_by_utc_not_file_timestamp_or_timezone_text():
    early = storage.build_scan("example.com", [], started_at="2026-10-01T12:00:00+02:00")
    selected = storage.build_scan("example.com", [], started_at="2026-10-01T11:00:00Z")
    future = storage.build_scan("example.com", [], started_at="2026-10-01T10:30:00-02:00")
    assert pipeline.scan_history(selected, [future, selected, early]) == [early, selected]
    report = build_report(selected, history=[future, early], generated_at=FIXED_TIME)
    assert len(report["history"]) == 2


def test_same_time_history_uses_scan_id_to_break_ties_and_selected_data_wins():
    scans = [storage.build_scan("example.com", [], started_at="2026-10-01T10:00:00Z") for _ in range(3)]
    for number, scan in enumerate(scans, 1):
        scan["scan_id"] = str(number)
    duplicate = copy.deepcopy(scans[1])
    duplicate["assets"] = [{"host": "unexpected.example.com", "ips": []}]
    assert pipeline.scan_history(scans[1], [scans[2], duplicate, scans[0]]) == scans[:2]


def test_temporary_regression_remains_in_history_when_net_state_is_unchanged():
    scans = [storage.build_scan("example.com", [{"host": "example.com", "ips": [
        {"ip": "192.0.2.10", "open_ports": []},
    ]}], started_at=f"2026-10-{number:02d}T10:00:00Z") for number in range(1, 5)]
    scans[1]["assets"][0]["ips"][0]["open_ports"] = [{"port": 21, "protocol": "tcp", "service": "ftp"}]
    before = json.dumps(scans, sort_keys=True)
    diff = pipeline.build_history_diff(scans[-1], scans, rules=[])
    assert diff["changes"] == [] and diff["summary"]["counts"]["total"] == 0
    kinds = [change["kind"] for step in diff["history"] for change in step["changes"]]
    assert "port.opened" in kinds and "port.closed" in kinds
    assert diff["history"][-1]["changes"][0]["status"] == "confirmed"
    assert json.dumps(scans, sort_keys=True) == before


def test_net_removal_is_not_confirmed_until_the_final_two_scans_agree():
    scans = [storage.build_scan("example.com", [{"host": "example.com", "ips": [
        {"ip": "192.0.2.10", "open_ports": []},
    ]}], started_at=f"2026-10-{number:02d}T10:00:00Z") for number in range(1, 6)]
    for index in (0, 2):
        scans[index]["assets"][0]["ips"][0]["open_ports"] = [{"port": 21, "protocol": "tcp", "service": "ftp"}]
    pending = pipeline.build_history_diff(scans[3], scans, rules=[])
    assert pending["changes"][0]["status"] == "missing"
    confirmed = pipeline.build_history_diff(scans[4], scans, rules=[])
    assert confirmed["changes"][0]["status"] == "confirmed"


def test_ignore_rules_apply_to_net_changes_and_every_history_step():
    scans = build_demo_scans()
    rules = [{"kind": "port.*", "host": "*"}]
    diff = pipeline.build_history_diff(scans[4], scans, rules=rules)
    for part in [diff, *diff["history"]]:
        assert not any(change["kind"].startswith("port.") for change in part["changes"])
        assert all(change["kind"].startswith("port.") for change in part["ignored"])
    assert any(step["ignored"] for step in diff["history"])


def test_all_renderers_keep_every_net_and_historical_change_line():
    net_lines = [f"Overall change {number}" for number in range(45)]
    history_lines = [f"Historical change {number}" for number in range(45)]
    diff = {"old": {"scan_id": "first"}, "new": {"scan_id": "last"},
            "summary": {"headline": "45 changes", "lines": net_lines},
            "history": [{"old": {"scan_id": "first"}, "new": {"scan_id": "last"},
                         "summary": {"headline": "45 historical changes", "lines": history_lines}}]}
    report = build_report(build_demo_scans()[-1], diff=diff, generated_at=FIXED_TIME)
    page, pdf, text = render_html(report), render_pdf(report), docx_text(render_docx(report))
    for line in [*net_lines, *history_lines]:
        assert html.escape(line) in page
        assert line.encode() in pdf
        assert line in text
