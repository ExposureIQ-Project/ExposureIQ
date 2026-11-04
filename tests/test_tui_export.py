"""Headless export interactions. Fake scans only; no network or scanning tools."""

import asyncio
import socket
import threading
import zipfile
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import Button, Static

from exposureiq import cli, storage
from exposureiq.report import render
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.export import ExportDialog

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"


@pytest.fixture(autouse=True)
def isolated_offline_environment(monkeypatch, tmp_path):
    attempts = []
    original_connect = socket.socket.connect

    def blocked_connect(sock, address, *args, **kwargs):
        if isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "::1", "localhost"):
            return original_connect(sock, address, *args, **kwargs)
        attempts.append(address)
        raise AssertionError("export tests must not use the network")

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("export tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.chdir(tmp_path)
    yield
    assert attempts == []


def scan_args(*flags):
    return cli.build_parser().parse_args(["scan", "example.com", "--demo", *flags])


def text(widget):
    value = widget.render()
    return value.plain if isinstance(value, Text) else str(value)


def saved_example(tmp_path, name="current.json", *, newer=False):
    snapshot = storage.load_scan(str(EXAMPLE))
    if newer:
        snapshot.update(scan_id="2026-10-14T12-00-00Z", started_at="2026-10-14T12:00:00Z")
        snapshot["assets"][0]["findings"][0]["title"] = "Newer saved evidence"
    directory = tmp_path / "results"
    directory.mkdir(exist_ok=True)
    path = directory / name
    storage.save_scan(snapshot, str(path))
    return path


def preview_app(tmp_path):
    source = saved_example(tmp_path)
    return ExposureIQApp(scan_args(), open_file=str(source), results_dir=source.parent)


@pytest.mark.parametrize("size", [(80, 24), (120, 40)])
def test_export_button_is_top_right_only_on_results(size, tmp_path):
    async def exercise():
        source = saved_example(tmp_path)
        app = ExposureIQApp(scan_args(), home=True, results_dir=source.parent)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            button = app.query_one("#export-report", Button)
            assert not button.display
            assert not app.check_action("export_report", ())
            app._show_scanning("example.com")
            await pilot.pause()
            assert not button.display
            assert app.open_saved(source)
            await pilot.pause()
            assert button.display and not button.disabled
            assert str(button.label) == "Export"
            assert button.region.right <= app.query_one("#topbar").content_region.right
            assert button.region.x > app.query_one("#mode-badge").region.right
            assert button.region.y == app.query_one("#mode-badge").region.y
            app._show_saved_list()
            assert not button.display
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("fmt", ["html", "docx"])
def test_scan_exports_selected_format_without_changing_default_pdf(fmt, tmp_path, monkeypatch):
    calls = []
    original_generate = render.generate_report
    ui_thread = threading.get_ident()

    def traced(source, **options):
        calls.append((source, options, threading.get_ident()))
        return original_generate(source, **options)

    monkeypatch.setattr(render, "generate_report", traced)

    async def exercise():
        app = ExposureIQApp(scan_args(), stages=cli._stages(), results_dir=tmp_path / "results")
        async with app.run_test(size=(100, 35)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.mode == "results"
            source, pdf = Path(app.result["saved_to"]), Path(app.result["report_to"])
            scan_bytes, pdf_bytes = source.read_bytes(), pdf.read_bytes()
            assert pdf_bytes.startswith(b"%PDF")
            calls.clear()
            await pilot.click("#export-report")
            await pilot.pause()
            assert isinstance(app.screen, ExportDialog)
            assert str(app.screen.query_one("#export-html", Button).label) == "HTML"
            assert str(app.screen.query_one("#export-docx", Button).label) == "DOCX"
            assert "report/" in text(app.screen.query_one("#export-destination", Static))
            assert not list((tmp_path / "report").rglob(f"*.{fmt}"))
            await pilot.click(f"#export-{fmt}")
            await app.export_worker.wait()
            await pilot.pause()
            path = Path(app.result["report_exports"][fmt])
            assert path.parent == Path("report/example.com")
            assert path.name == "index.html" if fmt == "html" else path.stem == pdf.stem
            assert path.suffix == f".{fmt}"
            assert path.is_file()
            assert not list((tmp_path / "report").rglob("*.docx" if fmt == "html" else "*.html"))
            if fmt == "html":
                assert "@keyframes" in path.read_text(encoding="utf-8")
            else:
                assert zipfile.is_zipfile(path)
            assert len(calls) == 1
            assert calls[0][0] == str(source)
            assert calls[0][1]["format"] == fmt
            assert calls[0][1]["results_dir"] == source.parent
            assert calls[0][2] != ui_thread
            assert source.read_bytes() == scan_bytes
            assert pdf.read_bytes() == pdf_bytes
            assert app.result["report_to"] == str(pdf)
            assert f"Report {fmt.upper()}" in text(app.query_one("#report-exports", Static))
            assert str(path) in text(app.query_one("#result-log", Static))
            assert not app._exporting
            assert not app.query_one("#export-report", Button).disabled
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("cancel", ["escape", "button"])
def test_cancel_export_writes_nothing(cancel, tmp_path):
    async def exercise():
        app = preview_app(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            source = Path(app.result["saved_to"])
            original = source.read_bytes()
            await pilot.press("e")
            assert isinstance(app.screen, ExportDialog)
            assert not app.check_action("export_report", ())
            if cancel == "escape":
                await pilot.press("escape")
            else:
                await pilot.click("#export-cancel")
            await pilot.pause()
            assert not isinstance(app.screen, ExportDialog)
            assert not (tmp_path / "report").exists()
            assert source.read_bytes() == original
            assert app.export_worker is None
            assert not app.query_one("#export-report", Button).disabled
            await pilot.press("q")

    asyncio.run(exercise())


def test_unsaved_scan_disables_export_and_explains_why(tmp_path):
    async def exercise():
        app = ExposureIQApp(scan_args("--no-save"), stages=cli._stages())
        async with app.run_test(size=(80, 24)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            button = app.query_one("#export-report", Button)
            assert button.display and button.disabled
            assert "saved scan" in button.tooltip
            assert not app.check_action("export_report", ())
            await pilot.press("e")
            assert not isinstance(app.screen, ExportDialog)
            assert not (tmp_path / "report").exists()
            await pilot.press("q")

    asyncio.run(exercise())


def test_no_report_flag_still_allows_manual_export(tmp_path):
    async def exercise():
        app = ExposureIQApp(scan_args("--no-report"), stages=cli._stages())
        async with app.run_test(size=(80, 24)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert not (tmp_path / "report").exists()
            await pilot.click("#export-report")
            await pilot.click("#export-html")
            await app.export_worker.wait()
            await pilot.pause()
            assert Path(app.result["report_exports"]["html"]).is_file()
            assert not list((tmp_path / "report").rglob("*.pdf"))
            await pilot.press("q")

    asyncio.run(exercise())


def test_export_failure_is_readable_and_can_be_retried(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("fake disk failure")

    monkeypatch.setattr(render, "generate_report", fail)

    async def exercise():
        app = preview_app(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.click("#export-report")
            await pilot.click("#export-docx")
            await app.export_worker.wait()
            await pilot.pause()
            assert "Could not export DOCX report: fake disk failure" in text(app.query_one("#result-log", Static))
            assert not app._exporting
            assert not app.query_one("#export-report", Button).disabled
            assert not app.result.get("report_exports")
            assert app.exit_code == 0
            await pilot.press("e")
            assert isinstance(app.screen, ExportDialog)
            await pilot.press("escape", "q")

    asyncio.run(exercise())


def test_deleted_source_is_an_export_error_not_a_crash(tmp_path):
    async def exercise():
        app = preview_app(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            Path(app.result["saved_to"]).unlink()
            await pilot.click("#export-report")
            await pilot.click("#export-html")
            await app.export_worker.wait()
            await pilot.pause()
            assert "Scan file not found" in text(app.query_one("#result-log", Static))
            assert not app._exporting
            assert not (tmp_path / "report").exists()
            await pilot.press("q")

    asyncio.run(exercise())


def test_export_uses_captured_scan_and_stays_responsive_when_user_navigates(tmp_path, monkeypatch, portal_html):
    entered, release = threading.Event(), threading.Event()
    original_generate = render.generate_report
    calls = []

    def delayed(source, **options):
        calls.append(source)
        entered.set()
        if not release.wait(5):
            raise AssertionError("test did not release the export worker")
        return original_generate(source, **options)

    monkeypatch.setattr(render, "generate_report", delayed)

    async def exercise():
        app = preview_app(tmp_path)
        newer = saved_example(tmp_path, "newer.json", newer=True)
        async with app.run_test(size=(100, 35)) as pilot:
            await pilot.pause()
            captured = app.result
            await pilot.press("e")
            await pilot.click("#export-html")
            try:
                await pilot.pause()
                assert entered.is_set()
                assert app._exporting
                assert app.query_one("#export-report", Button).disabled
                assert not app.check_action("add_scope", ())
                assert app.open_saved(newer)
                current = app.result
                await pilot.pause()
                await pilot.press("e")
                assert not isinstance(app.screen, ExportDialog)
                assert len(calls) == 1
            finally:
                release.set()
            await app.export_worker.wait()
            await pilot.pause()
            assert calls == [captured["saved_to"]]
            assert app.result is current
            assert not current.get("report_exports")
            page = Path(captured["report_exports"]["html"]).read_text(encoding="utf-8")
            parsed = portal_html(page)
            assert len(parsed.cards) == 2  # The domain home includes both saved scans.
            snapshot = storage.load_scan(captured["saved_to"])
            captured_view = parsed.views[(snapshot["scan_id"], snapshot["started_at"])]
            assert "Newer saved evidence" not in captured_view
            assert "Newer saved evidence" in page
            assert not app.query_one("#export-report", Button).disabled
            await pilot.press("q")

    asyncio.run(exercise())
