"""Selected-scan history in the TUI, using saved fixtures and blocked probes."""

import asyncio
import socket
import zipfile
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Static, TabPane

from exposureiq import cli, storage
from exposureiq.demo_data import build_demo_scans
from exposureiq.diffing import pipeline
from exposureiq.report import render
from exposureiq.tui.app import ExposureIQApp


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch, tmp_path):
    attempts = []
    original_connect = socket.socket.connect

    def blocked_connect(sock, address, *args, **kwargs):
        # Some asyncio event loops use a local socketpair, not a target probe.
        if isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "::1", "localhost"):
            return original_connect(sock, address, *args, **kwargs)
        attempts.append(address)
        raise AssertionError("TUI history must never use the network")

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("TUI history must never run real scan stages")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", blocked)
    monkeypatch.setattr(cli, "resolve_hosts", blocked)
    monkeypatch.setattr(cli, "_load_scope", blocked)
    monkeypatch.setattr(cli, "_load_checks", blocked)
    monkeypatch.setattr(cli, "_load_ports", blocked)
    monkeypatch.setattr(pipeline.noise, "load_ignore_rules", lambda: [])
    yield
    assert attempts == []


def text(widget):
    value = widget.render()
    return value.plain if isinstance(value, Text) else str(value)


def saved_story(directory, *, real=False):
    scans, paths = build_demo_scans(), []
    for number, scan in enumerate(scans, 1):
        if real:
            scan["scan_id"] = f"SCAN-{number:02d}"
        path = directory / f"scan_{number:02d}.json"
        storage.save_scan(scan, str(path))
        paths.append(path)
    return scans, paths


def assert_history_window(app, scans, number, prefix="scan-diff"):
    meta = text(app.query_one(f"#{prefix}-meta", Static))
    body = text(app.query_one(f"#{prefix}-body", Static))
    assert "baseline:" in meta and "selected:" in meta
    assert scans[0]["scan_id"] in meta and scans[number - 1]["scan_id"] in meta
    assert "Scan-by-scan history" in body
    assert all(scan["scan_id"] in body for scan in scans[:number])
    assert all(scan["scan_id"] not in meta + body for scan in scans[number:])


def test_demos_tui_finishes_on_scan_ten_with_complete_history(tmp_path):
    async def exercise():
        args = cli.build_parser().parse_args(["scan", "example.net", "--demos", "--no-report"])
        app = ExposureIQApp(args, stages=cli._stages())
        async with app.run_test(size=(110, 34)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            scans = build_demo_scans()
            assert app.mode == "results" and app.result["demo"]
            assert app.result["scan_id"] == scans[-1]["scan_id"]
            assert len(app.result["saved_scans"]) == 10
            assert app.query_one("#scan-diff-tab", TabPane).display
            assert_history_window(app, scans, 10)
            assert "HIGH 0" in text(app.query_one("#severity-high", Static))
            assert "MEDIUM 0" in text(app.query_one("#severity-medium", Static))
            assert "LOW 1" in text(app.query_one("#severity-low", Static))
            assert "10 of 10" in text(app.query_one("#summary-notes", Static))
            assert "DEMO" in text(app.query_one("#mode-badge", Static))
            assert not app.query_one("#export-report", Button).disabled
            assert not app.query_one("#add-scope", Button).display
            assert not (tmp_path / "report").exists()
            await pilot.click("#back")
            await pilot.pause()
            assert app.mode == "browser" and app.query_one("#saved-table", DataTable).row_count == 10
            await pilot.press("q")
        assert app.return_value == 0

    asyncio.run(exercise())


@pytest.mark.parametrize("output", [None, "story/"])
def test_demo_browser_keeps_the_results_root_and_separate_domains(tmp_path, output):
    root = Path(output or "results")
    other = storage.build_scan("example.net", [], started_at="2026-10-11T12:00:00Z")
    storage.save_scan(other, str(root / "example.net" / "other.json"))

    async def exercise():
        flags = ["scan", "example.com", "--demos", "--no-report"]
        if output:
            flags += ["-o", output]
        app = ExposureIQApp(cli.build_parser().parse_args(flags), stages=cli._stages())
        async with app.run_test(size=(110, 34)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert Path(app.results_dir) == root
            assert Path(app.result["saved_to"]).parent == root / "example.com"
            await pilot.click("#back")
            await pilot.pause()
            assert app.query_one("#saved-table", DataTable).row_count == 11
            assert {Path(path).parent.name for path in app.saved_paths.values()} == {"example.com", "example.net"}
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("number", [1, 3, 5, 10])
def test_preview_tab_and_diff_view_stop_at_the_selected_scan(tmp_path, number):
    scans, paths = saved_story(tmp_path / "results")
    before = [path.read_bytes() for path in paths]

    async def exercise():
        args = cli.build_parser().parse_args([])
        app = ExposureIQApp(args, open_file=str(paths[number - 1]))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert app.result["mode"] == "preview" and app.worker is None
            assert app.result["scan_id"] == scans[number - 1]["scan_id"]
            assert app.query_one("#scan-diff-tab", TabPane).display == (number > 1)
            if number > 1:
                assert_history_window(app, scans, number)
            app.action_diff_view()
            await pilot.pause()
            assert app.mode == "diff"
            assert not app.query_one("#export-report", Button).display
            assert not app.query_one("#scan-status", Static).display
            assert not app.query_one("#result-log", Static).display
            assert "DEMO" in text(app.query_one("#mode-badge", Static))
            if number > 1:
                assert_history_window(app, scans, number, "diff")
            else:
                assert "through the selected scan" in text(app.query_one("#diff-message", Static))
            await pilot.click("#back")
            await pilot.pause()
            assert app.mode == "browser"
            await pilot.press("q")

    asyncio.run(exercise())
    assert [path.read_bytes() for path in paths] == before


@pytest.mark.parametrize("real", [False, True])
def test_browser_diff_uses_selected_row_not_latest_scan(tmp_path, real):
    scans, paths = saved_story(tmp_path / "results", real=real)

    async def exercise():
        args = cli.build_parser().parse_args([])
        app = ExposureIQApp(args, home=True, browser=True)
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            table = app.query_one("#saved-table", DataTable)
            row = next(int(key) for key, path in app.saved_paths.items()
                       if Path(path).resolve() == paths[2].resolve())
            table.move_cursor(row=row)
            await pilot.click("#saved-diff-domain")
            await pilot.pause()
            assert app.mode == "diff"
            assert_history_window(app, scans, 3, "diff")
            assert ("DEMO" in text(app.query_one("#mode-badge", Static))) == (not real)
            await pilot.press("q")

    asyncio.run(exercise())


def test_demos_custom_output_keeps_the_browser_in_the_saved_folder(tmp_path):
    async def exercise():
        args = cli.build_parser().parse_args(["scan", "example.com", "--demos", "--no-report", "-o", "story/"])
        app = ExposureIQApp(args, stages=cli._stages())
        async with app.run_test(size=(110, 34)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert Path(app.results_dir) == Path("story")
            app.action_diff_view()
            await pilot.pause()
            assert_history_window(app, build_demo_scans(), 10, "diff")
            await pilot.click("#back")
            await pilot.pause()
            assert app.query_one("#saved-table", DataTable).row_count == 10
            assert all(Path(path).parent == Path("story/example.com") for path in app.saved_paths.values())
            await pilot.press("q")

    asyncio.run(exercise())
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize("fmt", ["html", "docx"])
def test_custom_folder_preview_diff_and_export_use_exact_selected_history(tmp_path, monkeypatch, fmt, portal_html):
    scans, paths = saved_story(tmp_path / "custom-results")
    before = [path.read_bytes() for path in paths]
    original_generate = render.generate_report
    selected = paths[4]
    automatic = original_generate(str(selected), format="pdf", results_dir=selected.parent,
                                  generated_at="2026-11-04T12:00:00Z")
    pdf = Path(automatic["pdf"])
    pdf_bytes = pdf.read_bytes()
    reports = []

    def traced(source, **options):
        result = original_generate(source, **options)
        reports.append(result)
        return result

    monkeypatch.setattr(render, "generate_report", traced)

    async def exercise():
        args = cli.build_parser().parse_args([])
        app = ExposureIQApp(args, open_file=str(selected))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert_history_window(app, scans, 5)
            app.action_diff_view()
            await pilot.pause()
            assert_history_window(app, scans, 5, "diff")
            assert app.open_saved(selected)
            await pilot.pause()
            await pilot.press("e")
            await pilot.click(f"#export-{fmt}")
            await app.export_worker.wait()
            await pilot.pause()
            assert len(reports) == 1
            report = reports[0]
            assert report["source"] == str(selected)
            assert [point["scan_id"] for point in report["report"]["history"]] == [scan["scan_id"] for scan in scans[:5]]
            assert len(report["diff"]["history"]) == 4
            path = Path(app.result["report_exports"][fmt])
            assert path.parent == Path("report/example.com")
            assert path.name == "index.html" if fmt == "html" else path.stem == pdf.stem
            if fmt == "html":
                page = path.read_text(encoding="utf-8")
                parsed = portal_html(page)
                assert len(parsed.cards) == 10
                page = parsed.views[(scans[4]["scan_id"], scans[4]["started_at"])]
            else:
                with zipfile.ZipFile(path) as archive:
                    page = archive.read("word/document.xml").decode("utf-8")
            assert all(scan["scan_id"] in page for scan in scans[:5])
            assert all(scan["scan_id"] not in page for scan in scans[5:])
            assert pdf.read_bytes() == pdf_bytes
            await pilot.press("q")

    asyncio.run(exercise())
    assert [path.read_bytes() for path in paths] == before


def test_opening_earlier_previews_clears_later_history(tmp_path):
    scans, paths = saved_story(tmp_path / "results")

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(paths[-1]))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert_history_window(app, scans, 10)
            assert app.open_saved(paths[2])
            await pilot.pause()
            assert_history_window(app, scans, 3)
            assert app.open_saved(paths[0])
            await pilot.pause()
            assert not app.query_one("#scan-diff-tab", TabPane).display
            for name in ("meta", "headline", "body", "message"):
                assert not text(app.query_one(f"#scan-diff-{name}", Static))
            await pilot.press("q")

    asyncio.run(exercise())
