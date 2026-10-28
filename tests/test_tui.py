"""Textual headless tests: fake jobs only, no internet or discovery tools.

Export presentation screenshots (also fake-only):
    python tests/test_tui.py --export-screens
"""

import asyncio
import logging
import socket
import threading
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import DataTable, ProgressBar, Static, TabbedContent, TabPane, Tabs

from exposureiq import cli
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.control import ScanControl
from exposureiq.tui.scan import PHASES, run_scan


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("TUI tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    assert attempts == []


def args(*flags):
    return cli.build_parser().parse_args(["scan", "example.com", *flags])


def fake_result():
    assets = [{"host": host, "ips": [{"ip": "192.0.2.10", "open_ports": [
        {"port": 443, "protocol": "tcp", "service": "https"},
    ]}], "technologies": [], "findings": []} for host in ("example.com", "api.example.com")]
    assets[1]["technologies"] = [{"name": "[bold]nginx[/bold]", "version": "1.18.0", "source": "DEMO Server header"}]
    assets[1]["findings"] = [{
        "id": "F-0001", "rule": "headers.missing_csp", "severity": "medium",
        "title": "DEMO: Missing content security policy", "detail": "[bold]saved sample detail[/bold]",
        "recommendation": "Add a Content-Security-Policy header.",
    }]
    assets[0]["findings"] = [{
        "id": "F-0002", "rule": "tech.server_version_disclosed", "severity": "low",
        "title": "DEMO: Server version disclosed", "detail": "DEMO: nginx/1.18.0 was in the saved header.",
        "recommendation": "Hide the Server version.",
    }]
    return {
        "target": "example.com", "demo": True, "names": ["api.example.com"],
        "assets": assets, "elapsed": 2.0, "saved_to": "results/demo_sample.json",
        "phase_states": dict.fromkeys(PHASES, "done"),
        "phase_counts": dict(zip(PHASES, (3, 1, 2, 2, 1, 2))),
        "phase_times": dict.fromkeys(PHASES, 0.2),
        "warnings": [], "skipped_hosts": [], "skipped_ips": [],
        "host_states": {host: "checked" for host in ("example.com", "api.example.com")},
        "port_rows": [("192.0.2.10", [{"port": 443, "protocol": "tcp", "service": "https"}])],
        "return_code": 0,
    }


class FakeJob:
    def __init__(self, finished=False):
        self.release = threading.Event()
        self.entered = threading.Event()
        self.thread_id = None
        if finished:
            self.release.set()

    def __call__(self, args, stages, report, control, version):
        self.thread_id = threading.get_ident()
        report({"kind": "phase", "phase": "Scope", "state": "done", "count": 3})
        report({"kind": "phase", "phase": "Subdomains", "state": "spinner", "count": None,
                "message": "DEMO: reading saved subdomain samples"})
        report({"kind": "counters", "subdomains": 1, "hosts": 2, "ips": 1, "findings": 1})
        self.entered.set()
        while not self.release.wait(0.02):
            control.check()
        control.check()
        return fake_result()


def plain_text(widget):
    rendered = widget.render()
    return rendered.plain if isinstance(rendered, Text) else str(rendered)


def test_scanning_screen_has_phases_live_counts_spinner_and_responsive_q():
    async def exercise():
        job = FakeJob()
        app = ExposureIQApp(args("--demo"), scan_job=job)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            assert job.entered.is_set() and job.thread_id != threading.get_ident()
            svg = app.export_screenshot(title="Scanning")
            assert "ExposureIQ" in svg and "example.com" in svg and "DEMO" in svg
            assert "quit/cancel" in svg and "Tab" in svg and "Enter" in svg
            brand = app.query_one("#brand", Static)
            assert brand.content_region.height >= 1
            assert app.query_one("#scanning").display
            assert not app.query_one("#results").display
            for index, phase in enumerate(PHASES):
                assert phase in plain_text(app.query_one(f"#phase-{index}", Static))
            assert "spinner" in plain_text(app.query_one("#phase-1", Static))
            assert "waiting" in plain_text(app.query_one("#phase-2", Static))
            assert app.query_one("#scan-progress", ProgressBar).total is None
            assert "Subdomains" in plain_text(app.query_one("#counters", Static))
            assert app.live_counts == dict(subdomains=1, hosts=2, ips=1, findings=1)
            before = plain_text(app.query_one("#elapsed", Static))
            await pilot.pause(0.2)
            assert plain_text(app.query_one("#elapsed", Static)) != before
            await pilot.press("q")
        assert app.return_value == 130 and app.control.cancelled.is_set()

    asyncio.run(exercise())


def test_results_tabs_grouped_hosts_and_finding_selection_shows_fix():
    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob(finished=True))
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert not app.query_one("#scanning").display and app.query_one("#results").display
            assert len(app.query(TabPane)) >= 6
            svg = app.export_screenshot(title="ExposureIQ DEMO results")
            assert "quit/cancel" in svg and "Tab" in svg and "Enter" in svg
            for label in ("Summary", "Subdomains", "Hosts", "Technologies", "Findings", "Ports"):
                assert label in svg
            assert "results/demo_sample.json" in plain_text(app.query_one("#summary-notes", Static))
            assert app.query_one("#hosts-table", DataTable).row_count == 1
            assert str(app.query_one("#hosts-table", DataTable).get_row_at(0)[1]) == "2"
            assert app.query_one("#subdomains-table", DataTable).row_count == 1
            assert app.query_one("#ports-table", DataTable).row_count == 1
            app.query_one("#results", TabbedContent).active = "findings-tab"
            await pilot.pause()
            app.query_one("#findings-table", DataTable).focus()
            await pilot.press("enter")
            detail = plain_text(app.query_one("#finding-detail", Static))
            assert "Fix: Add a Content-Security-Policy header." in detail
            assert "Rule: headers.missing_csp" in detail and "ID: F-0001" in detail
            assert "[bold]saved sample detail[/bold]" in detail
            await pilot.press("down", "enter")
            detail = plain_text(app.query_one("#finding-detail", Static))
            assert "Fix: Hide the Server version." in detail and "ID: F-0002" in detail
            app.query_one("#results Tabs", Tabs).focus()
            await pilot.press("right")
            assert app.query_one("#results", TabbedContent).active == "ports-tab"
            await pilot.press("tab")
            assert app.focused is not None
            await pilot.press("q")
        assert app.return_value == 0

    asyncio.run(exercise())


def test_ctrl_c_cancels_without_a_traceback(capsys):
    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob())
        async with app.run_test() as pilot:
            await pilot.pause(0.1)
            await pilot.press("ctrl+c")
        assert app.return_value == 130 and app.control.cancelled.is_set()

    asyncio.run(exercise())
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err


def test_failed_worker_shows_clean_error_and_q_returns_one(capsys):
    def failing(*args):
        raise OSError("fake disk failure")

    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=failing)
        async with app.run_test() as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert "fake disk failure" in plain_text(app.query_one("#live-log", Static))
            await pilot.press("q")
        assert app.return_value == 1

    asyncio.run(exercise())
    assert "Traceback" not in capsys.readouterr().err


def test_tui_demo_shared_pipeline_is_fake_only_and_saves_json(monkeypatch, tmp_path):
    from exposureiq import storage

    def blocked(*args, **kwargs):
        raise AssertionError("DEMO must not load or run real discovery/probe stages")

    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", blocked)
    monkeypatch.setattr(cli, "resolve_hosts", blocked)
    monkeypatch.setattr(cli, "_load_scope", blocked)
    monkeypatch.setattr(cli, "_load_checks", blocked)
    monkeypatch.setattr(cli, "_load_ports", blocked)
    path = tmp_path / "demo_tui.json"

    async def exercise():
        app = ExposureIQApp(args("--demo", "-o", str(path)), stages=cli._stages())
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.result["demo"] and app.result["return_code"] == 0
            assert app.query_one("#findings-table", DataTable).row_count == 5
            assert "DEMO" in plain_text(app.query_one("#brand", Static))
            assert app.query_one("#hosts-table", DataTable).row_count == 2
            await pilot.press("q")

    asyncio.run(exercise())
    snapshot = storage.load_scan(str(path))
    assert snapshot["scan_id"].startswith("DEMO-")
    assert {entry["ip"] for asset in snapshot["assets"] for entry in asset["ips"]} == {"192.0.2.10", "192.0.2.20"}


def test_tui_restores_logging_after_quit():
    handlers = logging.getLogger().handlers[:]

    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob(finished=True))
        async with app.run_test() as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("q")

    asyncio.run(exercise())
    assert logging.getLogger().handlers == handlers


def test_standard_80_by_24_terminal_shows_all_phases_and_live_counts():
    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob())
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause(0.2)
            for selector in ("#phase-5", "#counters", "#elapsed", "#scan-progress", "#live-log"):
                region = app.query_one(selector).region
                assert 0 <= region.y < 22 and region.bottom <= 22
            await pilot.press("q")

    asyncio.run(exercise())


def test_tui_demo_passive_shows_active_phases_as_skipped():
    async def exercise():
        app = ExposureIQApp(args("--demo", "--passive", "--no-save"), stages=cli._stages())
        async with app.run_test(size=(80, 24)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.result["phase_states"]["Web checks"] == "skipped"
            assert app.result["phase_states"]["Ports"] == "skipped"
            assert app.query_one("#findings-table", DataTable).row_count == 0
            assert "Not saved" in plain_text(app.query_one("#summary-notes", Static))
            await pilot.press("q")

    asyncio.run(exercise())


async def export_screens(directory: Path) -> list:
    """Hold a DEMO stage long enough to export the scanning SVG reliably."""
    release, entered = threading.Event(), threading.Event()
    directory.mkdir(parents=True, exist_ok=True)

    def job(args, stages, report, control, version):
        def events(event):
            report(event)
            if event["kind"] == "phase" and event["phase"] == "Subdomains" and event["state"] == "spinner":
                entered.set()
                while not release.wait(0.02):
                    control.check()
        return run_scan(args, stages, events, control, version)

    app = ExposureIQApp(args("--demo"),
                        stages=cli._stages(), control=ScanControl(), scan_job=job)
    paths = []
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        assert entered.is_set()
        path = directory / "scanning.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ DEMO — scanning"), encoding="utf-8")
        paths.append(path)
        release.set()
        await app.worker.wait()
        await pilot.pause()
        assert app.result["return_code"] == 0
        path = directory / "results.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ DEMO — results"), encoding="utf-8")
        paths.append(path)
        app.query_one("#results", TabbedContent).active = "findings-tab"
        await pilot.pause()
        app.query_one("#findings-table", DataTable).focus()
        await pilot.press("enter")
        path = directory / "findings.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ DEMO — finding and Fix"), encoding="utf-8")
        paths.append(path)
        await pilot.press("q")
    return paths


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--export-screens"]:
        raise SystemExit("Use python tests/test_tui.py --export-screens")
    for path in asyncio.run(export_screens(Path("/tmp/opencode/exposureiq-s2-tui-screens"))):
        print(path)
